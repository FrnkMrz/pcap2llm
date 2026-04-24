from __future__ import annotations

import json
import shutil
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pcap2llm.error_codes import map_error
from pcap2llm.privacy_profiles import list_privacy_profiles
from pcap2llm.profiles import list_profile_names

from .config import WebSettings, load_settings
from .jobs import JobStore
from .models import AnalyzeOptions, JobRecord, SecurityProfile, now_utc_iso
from .pcap_runner import Pcap2LlmRunner
from .profiles import ProfileStore
from .security import WebValidationError, reject_nested_filename, sanitize_filename, validate_capture_filename


def create_app(settings: WebSettings | None = None) -> FastAPI:
    settings = settings or load_settings()
    settings.workdir.mkdir(parents=True, exist_ok=True)

    app = FastAPI(title="pcap2llm Web GUI")
    app.state.settings = settings
    app.state.store = JobStore(settings.workdir)
    app.state.profile_store = ProfileStore(settings.workdir)
    app.state.runner = Pcap2LlmRunner(
        command_timeout_seconds=settings.command_timeout_seconds,
        default_tshark_path=settings.tshark_path,
    )

    web_dir = Path(__file__).resolve().parent
    templates = Jinja2Templates(directory=str(web_dir / "templates"))
    app.mount("/static", StaticFiles(directory=str(web_dir / "static")), name="static")

    @app.on_event("startup")
    async def startup_cleanup() -> None:
        """Run cleanup of old jobs on application startup if enabled."""
        if settings.cleanup_enabled:
            store: JobStore = app.state.store
            deleted = store.cleanup_old_jobs(settings.cleanup_max_age_days)
            if deleted > 0:
                print(f"[Cleanup] Removed {deleted} old job(s) (older than {settings.cleanup_max_age_days} days)")

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "settings": settings,
            },
        )

    @app.post("/jobs")
    async def create_job(
        request: Request,
        capture: UploadFile = File(...),
        auto_discover: bool = Form(False),
    ) -> RedirectResponse:
        if not capture.filename:
            raise HTTPException(status_code=400, detail="No file provided.")

        safe_name = sanitize_filename(capture.filename)
        try:
            validate_capture_filename(safe_name)
        except WebValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        store: JobStore = request.app.state.store
        runner: Pcap2LlmRunner = request.app.state.runner

        record = store.create(safe_name)
        record.status = "uploaded"
        store.save(record)

        capture_path = store.capture_path(record)
        total_size = 0
        with capture_path.open("wb") as out_fp:
            while True:
                chunk = await capture.read(1024 * 1024)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > settings.max_upload_bytes:
                    out_fp.close()
                    capture_path.unlink(missing_ok=True)
                    store.set_status(record.job_id, "failed", last_error="Upload exceeds configured size limit.")
                    raise HTTPException(status_code=413, detail="Upload exceeds configured size limit.")
                out_fp.write(chunk)

        if auto_discover:
            _run_discovery(store=store, runner=runner, record=record)

        return RedirectResponse(url=f"/jobs/{record.job_id}", status_code=303)

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    async def show_job(request: Request, job_id: str) -> HTMLResponse:
        store: JobStore = request.app.state.store
        runner: Pcap2LlmRunner = request.app.state.runner

        try:
            record = store.load(job_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Job not found.")

        capture_path = store.capture_path(record)
        selected_profile = record.selected_profile or _default_profile(record)
        selected_privacy = record.selected_privacy_profile or settings.default_privacy_profile
        analyze_defaults = _build_analyze_defaults(record)
        if not analyze_defaults.get("profile"):
            analyze_defaults["profile"] = selected_profile
        if not analyze_defaults.get("privacy_profile"):
            analyze_defaults["privacy_profile"] = selected_privacy

        preview = runner.build_command_preview(
            capture_path,
            AnalyzeOptions(profile=selected_profile, privacy_profile=selected_privacy),
            store.artifacts_dir(job_id),
        )

        context = {
            "request": request,
            "job": record,
            "profiles": list_profile_names(),
            "privacy_profiles": list_privacy_profiles(),
            "default_profiles": ["lte-core", "5g-core", "volte-ims-core", "vonr-ims-core", "2g3g-ss7-geran"],
            "preview": preview,
            "artifacts": store.sorted_artifacts(record),
            "downloads": store.list_download_entries(record),
            "stdout_log": _read_log(store.logs_dir(job_id) / "stdout.log"),
            "stderr_log": _read_log(store.logs_dir(job_id) / "stderr.log"),
            "flow_svg": _first_matching(store.artifacts_dir(job_id), ".svg"),
            "settings": settings,
            "analyze_defaults": analyze_defaults,
        }
        return templates.TemplateResponse("job.html", context)

    @app.post("/jobs/{job_id}/discover")
    async def run_discover(request: Request, job_id: str) -> RedirectResponse:
        store: JobStore = request.app.state.store
        runner: Pcap2LlmRunner = request.app.state.runner

        try:
            record = store.load(job_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Job not found.")

        _run_discovery(store=store, runner=runner, record=record)
        return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/analyze")
    async def run_analyze(
        request: Request,
        job_id: str,
        profile: str = Form(...),
        privacy_profile: str = Form("share"),
        display_filter: str = Form(""),
        max_packets: str = Form("1000"),
        all_packets: bool = Form(False),
        fail_on_truncation: bool = Form(False),
        max_capture_size_mb: str = Form(""),
        oversize_factor: str = Form(""),
        render_flow_svg: bool = Form(False),
        flow_title: str = Form(""),
        flow_max_events: str = Form(""),
        flow_svg_width: str = Form(""),
        collapse_repeats: bool = Form(False),
        hosts_file: str = Form(""),
        mapping_file: str = Form(""),
        subnets_file: str = Form(""),
        ss7pcs_file: str = Form(""),
        hosts_file_upload: UploadFile | None = File(None),
        mapping_file_upload: UploadFile | None = File(None),
        subnets_file_upload: UploadFile | None = File(None),
        ss7pcs_file_upload: UploadFile | None = File(None),
        tshark_path: str = Form(""),
        two_pass: bool = Form(False),
    ) -> RedirectResponse:
        store: JobStore = request.app.state.store
        runner: Pcap2LlmRunner = request.app.state.runner

        try:
            record = store.load(job_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Job not found.")

        try:
            hosts_path = await _resolve_support_file(
                store=store,
                record=record,
                label="hosts",
                raw_path=hosts_file,
                uploaded=hosts_file_upload,
            )
            mapping_path = await _resolve_support_file(
                store=store,
                record=record,
                label="mapping",
                raw_path=mapping_file,
                uploaded=mapping_file_upload,
            )
            subnets_path = await _resolve_support_file(
                store=store,
                record=record,
                label="subnets",
                raw_path=subnets_file,
                uploaded=subnets_file_upload,
            )
            ss7pcs_path = await _resolve_support_file(
                store=store,
                record=record,
                label="ss7pcs",
                raw_path=ss7pcs_file,
                uploaded=ss7pcs_file_upload,
            )

            options = AnalyzeOptions(
                profile=profile,
                privacy_profile=privacy_profile,
                display_filter=display_filter.strip() or None,
                max_packets=_parse_optional_int(max_packets),
                all_packets=all_packets,
                fail_on_truncation=fail_on_truncation,
                max_capture_size_mb=_parse_optional_int(max_capture_size_mb),
                oversize_factor=_parse_optional_float(oversize_factor),
                render_flow_svg=render_flow_svg,
                flow_title=flow_title.strip() or None,
                flow_max_events=_parse_optional_int(flow_max_events),
                flow_svg_width=_parse_optional_int(flow_svg_width),
                collapse_repeats=collapse_repeats,
                hosts_file=hosts_path,
                mapping_file=mapping_path,
                subnets_file=subnets_path,
                ss7pcs_file=ss7pcs_path,
                tshark_path=tshark_path.strip() or None,
                two_pass=two_pass,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid numeric analyze option.") from exc

        record.selected_profile = profile
        record.selected_privacy_profile = privacy_profile
        record.analyze_form = {
            "profile": profile,
            "privacy_profile": privacy_profile,
            "display_filter": display_filter.strip(),
            "max_packets": max_packets.strip(),
            "all_packets": all_packets,
            "fail_on_truncation": fail_on_truncation,
            "max_capture_size_mb": max_capture_size_mb.strip(),
            "oversize_factor": oversize_factor.strip(),
            "render_flow_svg": render_flow_svg,
            "flow_title": flow_title.strip(),
            "flow_max_events": flow_max_events.strip(),
            "flow_svg_width": flow_svg_width.strip(),
            "collapse_repeats": collapse_repeats,
            "hosts_file": hosts_file.strip(),
            "mapping_file": mapping_file.strip(),
            "subnets_file": subnets_file.strip(),
            "ss7pcs_file": ss7pcs_file.strip(),
            "tshark_path": tshark_path.strip(),
            "two_pass": two_pass,
        }
        store.save(record)

        _run_analyze(store=store, runner=runner, record=record, options=options)

        return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)

    @app.get("/jobs/{job_id}/status")
    async def job_status(request: Request, job_id: str) -> JSONResponse:
        store: JobStore = request.app.state.store
        try:
            record = store.load(job_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Job not found.")
        payload = record.to_dict()
        payload["artifacts"] = store.sorted_artifacts(record)
        return JSONResponse(payload)

    @app.get("/jobs/{job_id}/files/{filename}")
    async def download_file(request: Request, job_id: str, filename: str) -> FileResponse:
        store: JobStore = request.app.state.store
        try:
            record = store.load(job_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Job not found.")

        try:
            reject_nested_filename(filename)
            path = store.resolve_download(record, filename)
        except WebValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="File not found.")

        return FileResponse(path=path, filename=path.name)

    @app.get("/jobs/{job_id}/files/{section}/{filename}")
    async def download_file_scoped(request: Request, job_id: str, section: str, filename: str) -> FileResponse:
        store: JobStore = request.app.state.store
        try:
            record = store.load(job_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Job not found.")

        try:
            reject_nested_filename(filename)
            path = store.resolve_download_scoped(record, section, filename)
        except WebValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="File not found.")

        return FileResponse(path=path, filename=path.name)

    @app.get("/jobs/{job_id}/files.zip")
    async def download_zip(request: Request, job_id: str) -> StreamingResponse:
        store: JobStore = request.app.state.store
        try:
            record = store.load(job_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Job not found.")

        entries = store.collect_job_files_for_zip(record)
        if not entries:
            raise HTTPException(status_code=404, detail="No files available for archive.")

        buffer = BytesIO()
        with ZipFile(buffer, mode="w", compression=ZIP_DEFLATED) as zf:
            for arcname, source_path in entries:
                zf.write(source_path, arcname=arcname)
        buffer.seek(0)

        headers = {
            "Content-Disposition": f'attachment; filename="pcap2llm_job_{job_id}.zip"'
        }
        return StreamingResponse(buffer, media_type="application/zip", headers=headers)

    @app.post("/jobs/{job_id}/delete")
    async def delete_job(request: Request, job_id: str) -> RedirectResponse:
        store: JobStore = request.app.state.store
        root = store.job_root(job_id)
        if root.exists():
            shutil.rmtree(root)
        return RedirectResponse(url="/", status_code=303)

    @app.post("/admin/cleanup")
    async def admin_cleanup(request: Request, max_age_days: int | None = None) -> JSONResponse:
        """Manually trigger cleanup of old jobs. Returns count of deleted jobs."""
        store: JobStore = request.app.state.store
        age = max_age_days if max_age_days and max_age_days > 0 else settings.cleanup_max_age_days
        deleted = store.cleanup_old_jobs(age)
        return JSONResponse(
            {
                "status": "ok",
                "deleted_jobs": deleted,
                "max_age_days": age,
            }
        )

    @app.get("/profiles", response_class=HTMLResponse)
    async def list_profiles(request: Request, id: str | None = None) -> HTMLResponse:
        """Security Profiles management page."""
        profile_store: ProfileStore = request.app.state.profile_store
        profiles = profile_store.list_all()
        selected_profile = None

        if id:
            try:
                selected_profile = profile_store.load(id)
            except FileNotFoundError:
                pass

        if not selected_profile and profiles:
            selected_profile = profiles[0]

        context = {
            "request": request,
            "profiles": profiles,
            "selected_profile": selected_profile,
            "access_levels": ["read-only", "standard", "admin"],
            "network_options": ["internal-only", "vpn", "public"],
            "logging_levels": ["basic", "detailed", "security-events"],
        }
        return templates.TemplateResponse("profiles.html", context)

    @app.get("/api/profiles")
    async def api_list_profiles(request: Request) -> JSONResponse:
        """API: List all profiles as JSON."""
        profile_store: ProfileStore = request.app.state.profile_store
        profiles = profile_store.list_all()
        return JSONResponse([p.to_dict() for p in profiles])

    @app.post("/profiles")
    async def create_profile(
        request: Request,
        name: str = Form(...),
        description: str = Form(...),
        owner: str = Form(""),
        comment: str = Form(""),
    ) -> RedirectResponse:
        """Create a new security profile."""
        profile_store: ProfileStore = request.app.state.profile_store

        name = name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Profile name is required.")

        if profile_store.exists_by_name(name):
            raise HTTPException(status_code=400, detail=f"Profile '{name}' already exists.")

        profile = profile_store.create(name, description)
        profile.owner = owner.strip() or None
        profile.comment = comment.strip() or None
        profile_store.save(profile)

        return RedirectResponse(url=f"/profiles?id={profile.id}", status_code=303)

    @app.post("/profiles/{profile_id}")
    async def update_profile(
        request: Request,
        profile_id: str,
        name: str = Form(...),
        description: str = Form(...),
        status: str = Form("active"),
        owner: str = Form(""),
        comment: str = Form(""),
        auth_password: bool = Form(False),
        auth_mfa: bool = Form(False),
        auth_certificate: bool = Form(False),
        auth_access_level: str = Form("standard"),
        session_timeout_minutes: int = Form(30),
        network_access: str = Form("internal-only"),
        logging_level: str = Form("security-events"),
    ) -> RedirectResponse:
        """Update a security profile."""
        profile_store: ProfileStore = request.app.state.profile_store

        try:
            profile = profile_store.load(profile_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Profile not found.")

        name = name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="Profile name is required.")

        if name != profile.name and profile_store.exists_by_name(name):
            raise HTTPException(status_code=400, detail=f"Profile '{name}' already exists.")

        profile.name = name
        profile.description = description.strip()
        profile.status = status  # type: ignore
        profile.owner = owner.strip() or None
        profile.comment = comment.strip() or None
        profile.auth_password = auth_password
        profile.auth_mfa = auth_mfa
        profile.auth_certificate = auth_certificate
        profile.auth_access_level = auth_access_level  # type: ignore
        profile.session_timeout_minutes = max(1, session_timeout_minutes)
        profile.network_access = network_access  # type: ignore
        profile.logging_level = logging_level  # type: ignore

        profile_store.save(profile)
        return RedirectResponse(url=f"/profiles?id={profile_id}", status_code=303)

    @app.post("/profiles/{profile_id}/delete")
    async def delete_profile(request: Request, profile_id: str) -> RedirectResponse:
        """Delete a security profile."""
        profile_store: ProfileStore = request.app.state.profile_store
        profile_store.delete(profile_id)
        return RedirectResponse(url="/profiles", status_code=303)

    return app



def _run_discovery(*, store: JobStore, runner: Pcap2LlmRunner, record: JobRecord) -> None:
    store.set_status(record.job_id, "discovering")
    capture_path = store.capture_path(record)
    if not capture_path.exists():
        store.set_status(record.job_id, "failed", last_error="Uploaded file is missing.")
        return

    result = runner.discover(
        capture_path=capture_path,
        out_dir=store.discovery_dir(record.job_id),
        logs_dir=store.logs_dir(record.job_id),
    )
    if not result.ok:
        err, err_code = _friendly_error(result.stderr, default_message="Discovery failed. See stderr.log.")
        store.set_status(record.job_id, "failed", last_error=err, last_error_code=err_code)
        return

    job = store.load(record.job_id)
    discovery_json = _latest_json(store.discovery_dir(record.job_id))
    if discovery_json is not None:
        payload = _load_json_file(discovery_json)
        job.recommended_profiles = payload.get("candidate_profiles", [])
        job.suspected_domains = payload.get("suspected_domains", [])

        if not job.recommended_profiles:
            fallback = runner.recommend_profiles(discovery_json, logs_dir=store.logs_dir(record.job_id))
            if fallback.ok:
                fallback_payload = _load_json_text(fallback.stdout)
                job.recommended_profiles = fallback_payload.get("recommended_profiles", [])
                if not job.suspected_domains:
                    job.suspected_domains = fallback_payload.get("suspected_domains", [])

        if job.recommended_profiles and not job.selected_profile:
            job.selected_profile = str(job.recommended_profiles[0].get("profile", "")) or None
    job.status = "discovered"
    job.updated_at = now_utc_iso()
    job.last_error = None
    job.last_error_code = None
    store.save(job)



def _run_analyze(*, store: JobStore, runner: Pcap2LlmRunner, record: JobRecord, options: AnalyzeOptions) -> None:
    store.set_status(record.job_id, "analyzing")
    capture_path = store.capture_path(record)
    if not capture_path.exists():
        store.set_status(record.job_id, "failed", last_error="Uploaded file is missing.")
        return

    result = runner.analyze(
        capture_path=capture_path,
        options=options,
        out_dir=store.artifacts_dir(record.job_id),
        logs_dir=store.logs_dir(record.job_id),
    )
    if not result.ok:
        err, err_code = _friendly_error(result.stderr, default_message="Analyze failed. See stderr.log.")
        store.set_status(record.job_id, "failed", last_error=err, last_error_code=err_code)
        return

    job = store.load(record.job_id)
    artifacts = store.sorted_artifacts(job)
    if not artifacts:
        store.set_status(record.job_id, "failed", last_error="No artifacts were generated.", last_error_code="runtime_error")
        return

    job.status = "done"
    job.artifacts = artifacts
    job.last_error = None
    job.last_error_code = None
    job.updated_at = now_utc_iso()
    store.save(job)



def _default_profile(record: JobRecord) -> str:
    if record.recommended_profiles:
        candidate = str(record.recommended_profiles[0].get("profile", "")).strip()
        if candidate:
            return candidate
    return "lte-core"



def _parse_optional_int(value: str) -> int | None:
    text = value.strip()
    if not text:
        return None
    return int(text)


def _parse_optional_float(value: str) -> float | None:
    text = value.strip()
    if not text:
        return None
    return float(text)


async def _resolve_support_file(
    *,
    store: JobStore,
    record: JobRecord,
    label: str,
    raw_path: str,
    uploaded: UploadFile | None,
) -> str | None:
    if uploaded is not None and uploaded.filename:
        safe_name = sanitize_filename(uploaded.filename)
        support_dir = store.support_dir(record.job_id)
        support_dir.mkdir(parents=True, exist_ok=True)
        target = support_dir / f"{label}_{safe_name}"
        with target.open("wb") as out_fp:
            while True:
                chunk = await uploaded.read(1024 * 1024)
                if not chunk:
                    break
                out_fp.write(chunk)
        return str(target)

    text = raw_path.strip()
    return text or None



def _latest_json(folder: Path) -> Path | None:
    files = sorted((p for p in folder.glob("*.json") if p.is_file()), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None



def _first_matching(folder: Path, suffix: str) -> str | None:
    for path in sorted(folder.glob(f"*{suffix}")):
        if path.is_file():
            return path.name
    return None



def _read_log(path: Path) -> str:
    if not path.exists():
        return ""
    data = path.read_text(encoding="utf-8", errors="replace")
    return data[-8000:]


def _friendly_error(stderr: str, *, default_message: str) -> tuple[str, str]:
    text = (stderr or "").strip()
    if not text:
        return default_message, "runtime_error"

    code, _context = map_error(RuntimeError(text))
    mapped = {
        "tshark_missing": "TShark was not found in PATH.",
        "capture_too_large": "Upload exceeds configured size limit.",
        "detail_truncated_and_disallowed": "Analyze failed because fail-on-truncation was requested.",
        "invalid_tshark_json": "TShark returned invalid JSON output.",
        "capture_oversize": "Analyze aborted because capture exceeds oversize-factor policy.",
    }
    if "Command timed out" in text:
        return "Analyze command timed out.", "runtime_error"
    return mapped.get(code, text), code


def _build_analyze_defaults(record: JobRecord) -> dict[str, object]:
    defaults: dict[str, object] = {
        "profile": "",
        "privacy_profile": "",
        "display_filter": "",
        "max_packets": "1000",
        "all_packets": False,
        "fail_on_truncation": False,
        "max_capture_size_mb": "",
        "oversize_factor": "",
        "render_flow_svg": False,
        "flow_title": "",
        "flow_max_events": "",
        "flow_svg_width": "",
        "collapse_repeats": True,
        "hosts_file": "",
        "mapping_file": "",
        "subnets_file": "",
        "ss7pcs_file": "",
        "tshark_path": "",
        "two_pass": False,
    }
    for key, value in record.analyze_form.items():
        if key in defaults:
            defaults[key] = value
    return defaults


def _load_json_file(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_json_text(text: str) -> dict:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}



def main() -> None:
    settings = load_settings()
    app = create_app(settings)
    import uvicorn

    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
