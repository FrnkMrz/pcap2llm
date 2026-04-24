(function () {
  const root = document.querySelector("[data-job-id]");
  if (!root) {
    return;
  }

  const jobId = root.getAttribute("data-job-id");
  if (!jobId) {
    return;
  }

  const statusNode = document.querySelector("[data-job-status]");
  const errorNode = document.querySelector("[data-job-error]");
  const codeNode = document.querySelector("[data-job-error-code]");
  const progressing = new Set(["created", "uploaded", "discovering", "analyzing"]);
  let lastStatus = statusNode ? statusNode.textContent.trim() : "";

  async function tick() {
    try {
      const response = await fetch(`/jobs/${jobId}/status`, { cache: "no-store" });
      if (!response.ok) {
        return;
      }
      const payload = await response.json();
      const nextStatus = String(payload.status || "");

      if (statusNode) {
        statusNode.textContent = nextStatus;
      }
      if (errorNode) {
        errorNode.textContent = payload.last_error || "";
      }
      if (codeNode) {
        codeNode.textContent = payload.last_error_code || "";
      }

      if (lastStatus && nextStatus !== lastStatus) {
        window.location.reload();
        return;
      }
      lastStatus = nextStatus;

      if (!progressing.has(nextStatus)) {
        stop();
      }
    } catch (_err) {
      // Keep polling after transient failures.
    }
  }

  const timer = window.setInterval(tick, 3000);
  function stop() {
    window.clearInterval(timer);
  }

  tick();
})();