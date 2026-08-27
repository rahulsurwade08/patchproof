const STATUS_LABELS = {
  exploitable: "Exploitable",
  not_affected: "Not Affected",
  tests_pass: "Tests Pass",
  tests_fail: "Tests Fail",
  unknown: "Unknown",
};

function esc(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderScenario(s) {
  const evidence = s.verdict.evidence
    ? esc(s.verdict.evidence.slice(0, 60)) + "..."
    : "";
  const evidenceAttr = s.verdict.evidence ? esc(s.verdict.evidence) : "";
  return `
    <div class="card">
      <div class="card-header">
        <h3>${esc(s.cve_id)}</h3>
        <span class="badge badge-${s.status}">${STATUS_LABELS[s.status] || esc(s.status)}</span>
      </div>
      <div class="card-row">
        <span>Scenario</span>
        <span class="value">${esc(s.id)}</span>
      </div>
      <div class="card-row">
        <span>Dependency</span>
        <span class="value">${esc(s.dependency.name || "?")} ${esc(s.dependency.pinned_version || "")}</span>
      </div>
      <div class="card-row">
        <span>Expected</span>
        <span class="value">${esc(s.expected)}</span>
      </div>
      ${
        s.gate.passed !== undefined
          ? `<div class="card-row"><span>Gate</span><span class="value">${s.gate.passed ? "PASS" : "FAIL"}</span></div>`
          : ""
      }
      ${
        s.verdict.exploitable !== undefined
          ? `<div class="card-row"><span>Verdict</span><span class="value">${s.verdict.exploitable ? "EXPLOITABLE" : "NOT AFFECTED"}</span></div>`
          : ""
      }
      ${
        evidence
          ? `<div class="card-row"><span>Evidence</span><span class="value" title="${evidenceAttr}">${evidence}</span></div>`
          : ""
      }
    </div>
  `;
}

function renderEvent(e) {
  const cls = e.type === "exploit" ? "exploit" : e.type === "pass" ? "pass" : "";
  return `<div class="log-entry ${cls}"><span class="ts">[${esc(e.ts)}]</span> <span class="msg">${esc(e.message)}</span></div>`;
}

function renderApprovals(approvals) {
  if (!approvals || approvals.length === 0) {
    return '<div class="list-empty">No pending approvals</div>';
  }
  return approvals
    .map(
      (a) => `
    <div class="card-row">
      <span>${esc(a.scenario)} — ${esc(a.action)}</span>
      <span class="value">${esc(a.status)}</span>
    </div>`
    )
    .join("");
}

let eventSource;

function connect() {
  const dot = document.getElementById("connection-status");
  eventSource = new EventSource("/api/stream");

  eventSource.onopen = () => {
    dot.className = "status-dot connected";
  };

  eventSource.onerror = () => {
    dot.className = "status-dot disconnected";
  };

  eventSource.onmessage = (ev) => {
    try {
      const data = JSON.parse(ev.data);
      if (data.scenarios) {
        document.getElementById("scenario-grid").innerHTML =
          data.scenarios.map(renderScenario).join("");
      }
      if (data.events) {
        const log = document.getElementById("event-log");
        log.innerHTML = data.events.map(renderEvent).join("");
        log.scrollTop = log.scrollHeight;
      }
    } catch {}
  };
}

async function loadApprovals() {
  try {
    const resp = await fetch("/api/approvals");
    const data = await resp.json();
    document.getElementById("approval-list").innerHTML = renderApprovals(data);
  } catch {}
}

connect();
loadApprovals();
setInterval(loadApprovals, 5000);
