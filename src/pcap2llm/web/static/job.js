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
  const logbookNode = document.querySelector("[data-logbook]");
  const discoveryNode = document.querySelector("[data-discovery-panel]");
  const progressing = new Set(["created", "uploaded", "discovering", "analyzing"]);
  let lastStatus = statusNode ? statusNode.textContent.trim() : "";
  const storageKey = "pcap2llm-job-run-focus";

  function readPendingAction() {
    try {
      const raw = window.sessionStorage.getItem(storageKey);
      if (!raw) {
        return null;
      }
      const payload = JSON.parse(raw);
      if (payload.jobId !== jobId) {
        return null;
      }
      return payload;
    } catch (_err) {
      return null;
    }
  }

  function clearPendingAction() {
    window.sessionStorage.removeItem(storageKey);
  }

  function focusSection(target) {
    if (!target) {
      return;
    }
    if (target.tagName === "DETAILS") {
      target.open = true;
    }
    target.scrollIntoView({ behavior: "smooth", block: "start" });
    target.classList.add("panel-highlight");
    window.setTimeout(() => target.classList.remove("panel-highlight"), 1600);
  }

  function applyPendingFeedback() {
    const pending = readPendingAction();
    if (!pending) {
      return;
    }
    const feedback = document.querySelector(`[data-run-feedback="${pending.action}"]`);
    if (feedback) {
      feedback.textContent = pending.action === "discovery"
        ? "Discovery running, jumping to discovery results when finished..."
        : "Analysis running, jumping to logs when finished...";
    }
    if (!progressing.has(lastStatus)) {
      focusSection(pending.action === "discovery" ? discoveryNode || logbookNode : logbookNode);
      clearPendingAction();
    }
  }

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
        const pending = readPendingAction();
        if (pending && !progressing.has(nextStatus)) {
          pending.ready = true;
          window.sessionStorage.setItem(storageKey, JSON.stringify(pending));
        }
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

  document.querySelectorAll("form[data-run-action]").forEach((form) => {
    form.addEventListener("submit", () => {
      const action = form.getAttribute("data-run-action");
      const feedback = document.querySelector(`[data-run-feedback="${action}"]`);
      if (feedback) {
        feedback.textContent = action === "discovery"
          ? "Starting discovery..."
          : "Starting analysis...";
      }
      if (statusNode && action === "discovery") {
        statusNode.textContent = "discovering";
      }
      if (statusNode && action === "analyze") {
        statusNode.textContent = "analyzing";
      }
      window.sessionStorage.setItem(storageKey, JSON.stringify({ jobId, action, ts: Date.now() }));
    });
  });

  applyPendingFeedback();
  tick();
})();
