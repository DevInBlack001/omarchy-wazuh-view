// Formatting and status-aggregation helpers for the Wazuh View panel.
// Pure functions only, no QML/Quickshell imports, so this stays reusable
// and easy to reason about on its own.

function errorLabel(code) {
  var map = {
    permission_denied: "Permission denied, add your user to the wazuh group",
    not_found: "Not available yet",
    read_error: "Could not read local data",
    locked: "Database busy, the agent is writing to it right now",
  }
  return map[code] || "Unknown error"
}

// Three-tier status used for text/icon coloring: "good" | "warn" | "bad" |
// "unknown" (data not readable, distinct from a real pass/fail verdict).
function connectionStatus(connection) {
  if (!connection || !connection.readable) return "unknown"
  var status = (connection.fields && connection.fields.status) || ""
  if (status === "connected") return "good"
  if (status === "") return "unknown"
  return "bad"
}

function scaStatus(sca) {
  if (!sca || !sca.readable) return "unknown"
  if (sca.failedChecks && sca.failedChecks.length > 0) return "warn"
  return "good"
}

function fimStatus(fim) {
  if (!fim || !fim.readable) return "unknown"
  return "good"
}

function logStatus(logs) {
  if (!logs || !logs.readable) return "unknown"
  if (logs.errorCount > 0) return "bad"
  if (logs.warnCount > 0) return "warn"
  return "good"
}

function moduleStatus(enabled) {
  if (enabled === true) return "good"
  if (enabled === false) return "bad"
  return "unknown"
}

function worstStatus(statuses) {
  if (statuses.indexOf("bad") >= 0) return "bad"
  if (statuses.indexOf("warn") >= 0) return "warn"
  if (statuses.indexOf("unknown") >= 0) return "unknown"
  return "good"
}

function summarize(payload) {
  if (!payload) return { status: "unknown", label: "LOADING" }
  if (payload.installed === false) {
    return payload.blockedPath
      ? { status: "warn", label: "AGENT FOUND, NOT READABLE" }
      : { status: "unknown", label: "AGENT NOT DETECTED" }
  }

  var statuses = [
    connectionStatus(payload.connection),
    scaStatus(payload.sca),
    logStatus(payload.logs),
  ]
  var status = worstStatus(statuses)
  var label
  if (status === "bad") label = "ATTENTION NEEDED"
  else if (status === "warn") label = "CHECKS FAILING"
  else if (status === "unknown") label = "PARTIAL DATA"
  else label = "HEALTHY"
  return { status: status, label: label }
}

function totalsSummary(totals) {
  if (!totals) return "-"
  var parts = []
  for (var key in totals) {
    if (Object.prototype.hasOwnProperty.call(totals, key)) {
      parts.push(totals[key] + " " + key)
    }
  }
  return parts.length ? parts.join(", ") : "-"
}

function scanSummary(scan) {
  if (!scan) return "-"
  if (scan.pass !== null && scan.pass !== undefined && scan.total) {
    return scan.pass + " / " + scan.total + " passed"
  }
  return "-"
}

function fieldOrDash(v) {
  return (v === null || v === undefined || v === "") ? "-" : String(v)
}

function boolLabel(v) {
  if (v === true) return "yes"
  if (v === false) return "no"
  return "unknown"
}

if (typeof module !== "undefined") {
  module.exports = {
    errorLabel: errorLabel,
    connectionStatus: connectionStatus,
    scaStatus: scaStatus,
    fimStatus: fimStatus,
    logStatus: logStatus,
    moduleStatus: moduleStatus,
    worstStatus: worstStatus,
    summarize: summarize,
    totalsSummary: totalsSummary,
    scanSummary: scanSummary,
    fieldOrDash: fieldOrDash,
    boolLabel: boolLabel,
  }
}
