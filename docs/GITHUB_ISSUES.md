# GitHub Issue Drafts

This page turns the remaining roadmap and remediation items into copy-ready
GitHub issue drafts. The intent is to keep `v0.1.0` scoped and make later work
explicit.

## 1. Add Optional Authentication For The Web GUI

Labels: `security`, `web-gui`, `post-0.1.0`

The Web GUI is local-first and currently has no authentication or authorization.
That is acceptable for localhost use, but not for remote exposure.

Acceptance:

- Add an opt-in authentication mode for the Web GUI.
- Support at least one simple local operator flow, such as bearer token or API
  key via environment variable.
- Keep localhost-only behavior simple when auth is not configured.
- Add tests for allowed and rejected requests.
- Update `docs/WEB_GUI.md`, `docs/SECURITY_AUDIT_WEB_GUI.md`, and
  `docs/PROJECT_STATUS.md`.

## 2. Add Rate Limiting To Web GUI POST Routes

Labels: `security`, `web-gui`, `post-0.1.0`

The Web GUI has upload size limits and validation, but no request-rate limits.
This leaves local denial-of-service paths open if the GUI is exposed beyond a
single trusted operator.

Acceptance:

- Add rate limits for job creation, profile mutations, cleanup, delete routes,
  and analyze/discover triggers.
- Keep defaults friendly for localhost use.
- Make limits configurable through environment variables or settings.
- Add tests for limit hit and normal operation.
- Document the behavior in `docs/WEB_GUI.md`.

## 3. Build A TShark Compatibility Matrix

Labels: `compatibility`, `ci`, `tshark`

CI currently tests the Ubuntu-packaged TShark version available on
`ubuntu-latest`. Other Wireshark/TShark versions may work, but the project does
not yet publish a compatibility matrix.

Acceptance:

- Define the minimum supported TShark version.
- Add documented manual or automated checks for at least two TShark lines.
- Capture known field-name differences that affect LTE, 5G, IMS, DNS, and
  HTTP/2 profiles.
- Update `docs/SUPPORTED_ENVIRONMENTS.md`.

## 4. Add Release Automation For GitHub Releases

Labels: `release`, `ci`, `packaging`

The package can now be built and validated in CI, but release creation is still
manual.

Acceptance:

- Add a tag-triggered workflow for release builds.
- Upload wheel and sdist artifacts to the GitHub Release.
- Reuse existing metadata and wheel-content checks.
- Keep PyPI publishing out of scope unless explicitly enabled later.
- Document the release process in `docs/RELEASE_CHECKLIST.md`.

## 5. Improve Web GUI Error Messages For Validation Failures

Labels: `web-gui`, `ux`

Validation failures are handled, but some messages are still technical. The Web
GUI should make common operator errors clear without hiding the exact reason.

Acceptance:

- Review upload-limit, support-file, Origin/Referer, path, and analysis-limit
  failures.
- Display concise user-facing messages in the Web GUI.
- Keep detailed logs available for debugging.
- Add route tests for representative messages.

## 6. Review And Close Remaining Remediation-Plan Items

Labels: `maintenance`, `security`, `docs`

`docs/REMEDIATION_PLAN.md` still contains historical findings. Some are already
implemented and marked, while others need a final close-or-convert pass.

Acceptance:

- Review every open remediation item.
- Convert real remaining work into GitHub issues.
- Mark completed items as implemented.
- Move obsolete historical notes into a short archived section.
