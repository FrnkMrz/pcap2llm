from __future__ import annotations

import csv
import html
import json
import shutil
from contextlib import asynccontextmanager
from io import BytesIO, StringIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from pcap2llm.config import build_privacy_modes
from pcap2llm.error_codes import map_error
from pcap2llm.models import DATA_CLASSES
from pcap2llm.privacy_profiles import list_privacy_profiles, load_privacy_profile
from pcap2llm.profiles import list_profile_names

from .config import WebSettings, load_settings
from .jobs import JobStore
from .models import AnalyzeOptions, JobRecord, now_utc_iso
from .pcap_runner import Pcap2LlmRunner
from .profiles import ProfileStore
from .security import WebValidationError, reject_nested_filename, sanitize_filename, validate_capture_filename, validate_profile_name, validate_string_length


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next: ASGIApp) -> StreamingResponse:  # type: ignore
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


def create_app(settings: WebSettings | None = None) -> FastAPI:
    settings = settings or load_settings()
    settings.workdir.mkdir(parents=True, exist_ok=True)
    settings.security_profiles_dir.mkdir(parents=True, exist_ok=True)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Run startup cleanup via lifespan to stay compatible with current FastAPI."""
        if settings.cleanup_enabled:
            store: JobStore = app.state.store
            deleted = store.cleanup_old_jobs(settings.cleanup_max_age_days)
            if deleted > 0:
                print(f"[Cleanup] Removed {deleted} old job(s) (older than {settings.cleanup_max_age_days} days)")
        yield

    app = FastAPI(title="pcap2llm Web GUI", lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware)
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

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        store: JobStore = request.app.state.store
        jobs = store.list_all()
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "request": request,
                "settings": settings,
                "jobs": jobs,
            },
        )

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        """Dashboard with job and profile statistics."""
        store: JobStore = request.app.state.store
        profile_store: ProfileStore = request.app.state.profile_store

        job_stats = store.get_stats()
        profile_stats = profile_store.get_stats()

        context = {
            "request": request,
            "job_stats": job_stats,
            "profile_stats": profile_stats,
        }
        return templates.TemplateResponse(request=request, name="dashboard.html", context=context)

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
        profile_store: ProfileStore = request.app.state.profile_store

        try:
            record = store.load(job_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Job not found.")

        capture_path = store.capture_path(record)
        selected_profile = record.selected_profile or _default_profile(record)
        selected_privacy = record.selected_privacy_profile or settings.default_privacy_profile
        local_support_defaults = _local_support_file_defaults(settings)
        analyze_defaults = _build_analyze_defaults(record, local_support_defaults)
        if not analyze_defaults.get("profile"):
            analyze_defaults["profile"] = selected_profile
        if not analyze_defaults.get("privacy_profile"):
            analyze_defaults["privacy_profile"] = selected_privacy

        preview = runner.build_command_preview(
            capture_path,
            _build_preview_options(profile_store, analyze_defaults, selected_profile, selected_privacy),
            store.artifacts_dir(job_id),
        )

        context = {
            "request": request,
            "job": record,
            "profiles": list_profile_names(),
            "privacy_profiles": _privacy_profile_options(profile_store),
            "default_profiles": ["lte-core", "5g-core", "volte-ims-core", "vonr-ims-core", "2g3g-ss7-geran"],
            "preview": preview,
            "artifacts": store.sorted_artifacts(record),
            "downloads": store.list_download_entries(record),
            "log_sections": _collect_log_sections(store.logs_dir(job_id)),
            "flow_svg": _first_matching(store.artifacts_dir(job_id), ".svg"),
            "settings": settings,
            "analyze_defaults": analyze_defaults,
        }
        return templates.TemplateResponse(request=request, name="job.html", context=context)

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
        profile_store: ProfileStore = request.app.state.profile_store

        try:
            record = store.load(job_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Job not found.")

        try:
            local_support_defaults = _local_support_file_defaults(settings)
            hosts_path = await _resolve_support_file(
                store=store,
                record=record,
                label="hosts",
                raw_path=hosts_file,
                uploaded=hosts_file_upload,
                default_path=local_support_defaults["hosts_file"],
            )
            mapping_path = await _resolve_support_file(
                store=store,
                record=record,
                label="mapping",
                raw_path=mapping_file,
                uploaded=mapping_file_upload,
                default_path=local_support_defaults["mapping_file"],
            )
            subnets_path = await _resolve_support_file(
                store=store,
                record=record,
                label="subnets",
                raw_path=subnets_file,
                uploaded=subnets_file_upload,
                default_path=local_support_defaults["subnets_file"],
            )
            ss7pcs_path = await _resolve_support_file(
                store=store,
                record=record,
                label="ss7pcs",
                raw_path=ss7pcs_file,
                uploaded=ss7pcs_file_upload,
                default_path=local_support_defaults["ss7pcs_file"],
            )

            options = AnalyzeOptions(
                profile=profile,
                privacy_profile=_resolve_privacy_profile_cli_value(profile_store, privacy_profile),
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

    @app.get("/jobs/{job_id}/view/{section}/{filename}", response_class=HTMLResponse)
    async def view_text_file(request: Request, job_id: str, section: str, filename: str) -> HTMLResponse:
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

        if path.suffix.lower() != ".md":
            raise HTTPException(status_code=400, detail="Inline preview is currently supported for .md files only.")

        content = path.read_text(encoding="utf-8", errors="replace")
        escaped_content = html.escape(content)
        return HTMLResponse(
            f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{html.escape(path.name)} - pcap2llm</title>
    <style>
      body {{
        margin: 0;
        padding: 24px;
        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #f6f8fb;
        color: #16202a;
      }}
      .wrap {{
        max-width: 1100px;
        margin: 0 auto;
      }}
      .actions {{
        display: flex;
        gap: 12px;
        align-items: center;
        margin-bottom: 16px;
      }}
      a {{
        color: #1251a3;
        text-decoration: none;
      }}
      a:hover {{
        text-decoration: underline;
      }}
      pre {{
        white-space: pre-wrap;
        word-break: break-word;
        background: #ffffff;
        border: 1px solid #d7dee8;
        border-radius: 8px;
        padding: 16px;
        overflow: auto;
        line-height: 1.5;
      }}
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="actions">
        <a href="/jobs/{job_id}">Zurueck zum Job</a>
        <a href="/jobs/{job_id}/files/{section}/{filename}">Datei herunterladen</a>
      </div>
      <h1>{html.escape(path.name)}</h1>
      <pre>{escaped_content}</pre>
    </div>
  </body>
</html>"""
        )

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

    @app.post("/jobs/bulk-delete")
    async def bulk_delete_jobs(request: Request) -> RedirectResponse:
        """Delete multiple jobs at once."""
        store: JobStore = request.app.state.store
        form_data = await request.form()
        job_ids = form_data.getlist("job_id")
        
        for job_id in job_ids:
            try:
                reject_nested_filename(job_id)
            except WebValidationError:
                continue
            root = store.job_root(job_id)
            if root.exists():
                shutil.rmtree(root)
        
        return RedirectResponse(url="/", status_code=303)

    @app.post("/admin/cleanup")
    async def admin_cleanup(request: Request, max_age_days: int | None = None) -> JSONResponse:
        """Manually trigger cleanup of old jobs. Returns count of deleted jobs."""
        store: JobStore = request.app.state.store
        age = max_age_days
        if age is None:
            try:
                payload = await request.json()
                if isinstance(payload, dict):
                    maybe_age = payload.get("max_age_days")
                    if isinstance(maybe_age, int):
                        age = maybe_age
            except Exception:
                age = None

        age = age if age and age > 0 else settings.cleanup_max_age_days
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
        """Local privacy profile management page."""
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
            "privacy_profiles": _builtin_privacy_profiles(),
            "selected_profile": selected_profile,
            "data_classes": DATA_CLASSES,
            "protection_modes": ["keep", "mask", "pseudonymize", "encrypt", "remove"],
        }
        return templates.TemplateResponse(request=request, name="profiles.html", context=context)

    @app.get("/api/profiles")
    async def api_list_profiles(request: Request) -> JSONResponse:
        """API: List all profiles as JSON."""
        profile_store: ProfileStore = request.app.state.profile_store
        profiles = profile_store.list_all()
        return JSONResponse([p.to_dict() for p in profiles])

    @app.get("/profiles/export")
    async def export_profiles(request: Request, fmt: str = "json") -> StreamingResponse:
        """Export local privacy profiles in JSON or CSV format."""
        profile_store: ProfileStore = request.app.state.profile_store
        profiles = profile_store.list_all()

        if fmt == "json":
            payload = [p.to_dict() for p in profiles]
            body = json.dumps(payload, indent=2)
            headers = {
                "Content-Disposition": 'attachment; filename="privacy_profiles.json"'
            }
            return StreamingResponse(iter([body]), media_type="application/json", headers=headers)

        if fmt == "csv":
            out = StringIO()
            fieldnames = ["id", "name", "description", *DATA_CLASSES, "created_at", "updated_at"]
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()
            for profile in profiles:
                row = {
                    "id": profile.id,
                    "name": profile.name,
                    "description": profile.description,
                    "created_at": profile.created_at,
                    "updated_at": profile.updated_at,
                }
                for data_class in DATA_CLASSES:
                    row[data_class] = profile.modes.get(data_class, "keep")
                writer.writerow(row)
            headers = {
                "Content-Disposition": 'attachment; filename="privacy_profiles.csv"'
            }
            return StreamingResponse(iter([out.getvalue()]), media_type="text/csv", headers=headers)

        raise HTTPException(status_code=400, detail="Unsupported format. Use fmt=json or fmt=csv.")

    @app.post("/profiles")
    async def create_profile(
        request: Request,
        name: str = Form(...),
        description: str = Form(...),
    ) -> RedirectResponse:
        """Create a new local privacy profile."""
        profile_store: ProfileStore = request.app.state.profile_store

        # Validate and sanitize inputs
        name = name.strip()
        description = description.strip()

        try:
            validate_profile_name(name)
            validate_string_length(description, 1000, "Description")
        except WebValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if profile_store.exists_by_name(name):
            raise HTTPException(status_code=400, detail=f"Profile '{name}' already exists.")

        profile = profile_store.create(name, description)
        profile_store.save(profile)

        return RedirectResponse(url=f"/profiles?id={profile.id}", status_code=303)

    @app.post("/profiles/{profile_id}")
    async def update_profile(
        request: Request,
        profile_id: str,
        name: str = Form(...),
        description: str = Form(...),
    ) -> RedirectResponse:
        """Update a local privacy profile."""
        profile_store: ProfileStore = request.app.state.profile_store

        try:
            profile = profile_store.load(profile_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Profile not found.")

        # Validate and sanitize inputs
        name = name.strip()
        description = description.strip()

        try:
            validate_profile_name(name)
            validate_string_length(description, 1000, "Description")
        except WebValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if name != profile.name and profile_store.exists_by_name(name):
            raise HTTPException(status_code=400, detail=f"Profile '{name}' already exists.")

        try:
            profile_modes = _profile_modes_from_form(await request.form())
        except WebValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        profile.name = name
        profile.description = description
        profile.modes = profile_modes

        profile_store.save(profile)
        return RedirectResponse(url=f"/profiles?id={profile_id}", status_code=303)

    @app.post("/profiles/{profile_id}/delete")
    async def delete_profile(request: Request, profile_id: str) -> RedirectResponse:
        """Delete a local privacy profile."""
        profile_store: ProfileStore = request.app.state.profile_store
        profile_store.delete(profile_id)
        return RedirectResponse(url="/profiles", status_code=303)

    @app.post("/profiles/{profile_id}/duplicate")
    async def duplicate_profile(request: Request, profile_id: str) -> RedirectResponse:
        """Duplicate an existing profile with a unique copied name."""
        profile_store: ProfileStore = request.app.state.profile_store
        try:
            original = profile_store.load(profile_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Profile not found.")

        candidate = _next_profile_copy_name(profile_store, original.name)
        clone = profile_store.create(candidate, original.description, original.modes)
        profile_store.save(clone)

        return RedirectResponse(url=f"/profiles?id={clone.id}", status_code=303)

    @app.post("/profiles/privacy/{profile_name}/duplicate")
    async def duplicate_privacy_profile(request: Request, profile_name: str) -> RedirectResponse:
        """Create a local editable profile from a built-in privacy profile."""
        profile_store: ProfileStore = request.app.state.profile_store

        try:
            builtin = load_privacy_profile(profile_name)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Privacy profile not found.")

        candidate = _next_profile_copy_name(profile_store, builtin.name)
        clone = profile_store.create(candidate, builtin.description, builtin.modes)
        profile_store.save(clone)

        return RedirectResponse(url=f"/profiles?id={clone.id}", status_code=303)

    @app.post("/profiles/actions/bulk-delete")
    async def bulk_delete_profiles(request: Request) -> RedirectResponse:
        """Delete multiple profiles at once."""
        profile_store: ProfileStore = request.app.state.profile_store
        form_data = await request.form()
        profile_ids = form_data.getlist("profile_id")
        
        for profile_id in profile_ids:
            try:
                reject_nested_filename(profile_id)
            except WebValidationError:
                continue
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
    default_path: str,
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
    return text or default_path or None



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


def _collect_log_sections(logs_dir: Path) -> list[dict[str, str]]:
    sections: list[dict[str, str]] = []
    for prefix, label in (
        ("discovery", "Discovery"),
        ("recommend", "Recommendation"),
        ("analyze", "Analyze"),
    ):
        stdout = _read_log(logs_dir / f"{prefix}_stdout.log")
        stderr = _read_log(logs_dir / f"{prefix}_stderr.log")
        if stdout or stderr:
            sections.append(
                {
                    "label": label,
                    "stdout_name": f"{prefix}_stdout.log",
                    "stderr_name": f"{prefix}_stderr.log",
                    "stdout": stdout,
                    "stderr": stderr,
                }
            )

    if sections:
        return sections

    stdout = _read_log(logs_dir / "stdout.log")
    stderr = _read_log(logs_dir / "stderr.log")
    if stdout or stderr:
        return [
            {
                "label": "Run",
                "stdout_name": "stdout.log",
                "stderr_name": "stderr.log",
                "stdout": stdout,
                "stderr": stderr,
            }
        ]
    return []


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


def _next_profile_copy_name(profile_store: ProfileStore, base_name: str) -> str:
    candidate = f"{base_name} Copy"
    suffix = 2
    while profile_store.exists_by_name(candidate):
        candidate = f"{base_name} Copy {suffix}"
        suffix += 1
    return candidate


def _profile_modes_from_form(form_data) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for data_class in DATA_CLASSES:
        overrides[data_class] = str(form_data.get(f"mode_{data_class}", "keep"))
    try:
        return build_privacy_modes({}, overrides)
    except ValueError as exc:
        raise WebValidationError(str(exc)) from exc


def _build_analyze_defaults(record: JobRecord, local_support_defaults: dict[str, str]) -> dict[str, object]:
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
        "hosts_file": local_support_defaults["hosts_file"],
        "mapping_file": local_support_defaults["mapping_file"],
        "subnets_file": local_support_defaults["subnets_file"],
        "ss7pcs_file": local_support_defaults["ss7pcs_file"],
        "tshark_path": "",
        "two_pass": False,
    }
    for key, value in record.analyze_form.items():
        if key in defaults:
            defaults[key] = value
    return defaults


def _build_preview_options(
    profile_store: ProfileStore,
    analyze_defaults: dict[str, object],
    selected_profile: str,
    selected_privacy: str,
) -> AnalyzeOptions:
    return AnalyzeOptions(
        profile=str(analyze_defaults.get("profile") or selected_profile),
        privacy_profile=_resolve_privacy_profile_cli_value(
            profile_store,
            str(analyze_defaults.get("privacy_profile") or selected_privacy),
        ),
        display_filter=_string_or_none(analyze_defaults.get("display_filter")),
        max_packets=_parse_optional_int(str(analyze_defaults.get("max_packets", ""))),
        all_packets=bool(analyze_defaults.get("all_packets")),
        fail_on_truncation=bool(analyze_defaults.get("fail_on_truncation")),
        max_capture_size_mb=_parse_optional_int(str(analyze_defaults.get("max_capture_size_mb", ""))),
        oversize_factor=_parse_optional_float(str(analyze_defaults.get("oversize_factor", ""))),
        render_flow_svg=bool(analyze_defaults.get("render_flow_svg")),
        flow_title=_string_or_none(analyze_defaults.get("flow_title")),
        flow_max_events=_parse_optional_int(str(analyze_defaults.get("flow_max_events", ""))),
        flow_svg_width=_parse_optional_int(str(analyze_defaults.get("flow_svg_width", ""))),
        collapse_repeats=bool(analyze_defaults.get("collapse_repeats", True)),
        hosts_file=_string_or_none(analyze_defaults.get("hosts_file")),
        mapping_file=_string_or_none(analyze_defaults.get("mapping_file")),
        subnets_file=_string_or_none(analyze_defaults.get("subnets_file")),
        ss7pcs_file=_string_or_none(analyze_defaults.get("ss7pcs_file")),
        tshark_path=_string_or_none(analyze_defaults.get("tshark_path")),
        two_pass=bool(analyze_defaults.get("two_pass")),
    )


def _local_support_file_defaults(settings: WebSettings) -> dict[str, str]:
    local_root = settings.local_workspace_dir
    mapping_path = ""
    for candidate in (
        local_root / "mapping.yaml",
        local_root / "mapping.yml",
        local_root / "mapping.json",
    ):
        if candidate.exists():
            mapping_path = str(candidate)
            break
    return {
        "hosts_file": str(local_root / "hosts") if (local_root / "hosts").exists() else "",
        "mapping_file": mapping_path,
        "subnets_file": str(local_root / "Subnets") if (local_root / "Subnets").exists() else "",
        "ss7pcs_file": str(local_root / "ss7pcs") if (local_root / "ss7pcs").exists() else "",
    }


def _string_or_none(value: object) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _privacy_profile_options(profile_store: ProfileStore) -> list[dict[str, str]]:
    options = _builtin_privacy_profiles()
    for profile in profile_store.list_all():
        options.append(
            {
                "name": profile.name,
                "description": profile.description,
                "value": f"local:{profile.id}",
                "kind": "local",
                "summary": _privacy_mode_summary(profile.modes),
            }
        )
    return options


def _builtin_privacy_profiles() -> list[dict[str, str]]:
    options: list[dict[str, str]] = []
    for name in list_privacy_profiles():
        profile = load_privacy_profile(name)
        options.append(
            {
                "name": profile.name,
                "description": profile.description,
                "value": profile.name,
                "kind": "built-in",
                "summary": _privacy_mode_summary(profile.modes),
            }
        )
    return options


def _resolve_privacy_profile_cli_value(profile_store: ProfileStore, selection: str) -> str:
    profile_id = _local_profile_id(selection)
    if profile_id is None:
        return selection
    return str(profile_store.profile_path(profile_id))


def _local_profile_id(selection: str) -> str | None:
    if not selection.startswith("local:"):
        return None
    profile_id = selection.split(":", 1)[1].strip()
    return profile_id or None


def _privacy_mode_summary(modes: dict[str, str]) -> str:
    counts: dict[str, int] = {}
    normalized = build_privacy_modes({}, modes)
    for mode in normalized.values():
        counts[mode] = counts.get(mode, 0) + 1
    ordered = ["keep", "mask", "pseudonymize", "encrypt", "remove"]
    return ", ".join(f"{mode} {counts[mode]}" for mode in ordered if counts.get(mode))


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
