  // -- Plugin consoles: top bar pills -----------------------------------------
  //
  // A console may declare up to three pills. GET /api/plugin-consoles/pills
  // answers the ones that carry a value right now (a stopped console answers
  // none), and the top bar shows them beside the bridge pills with the same
  // classes, so they fold away at the same narrow widths. A click opens the
  // console. The poll runs only while a listed console declares pills and
  // rests while the page is hidden; showing the page asks again at once.

  var PC_PILLS_POLL_MS = 5000;
  // Pill tones onto the states the bridge pills already style.
  var PC_PILL_TONES = { ok: "running", warn: "warn", error: "error", busy: "configured", idle: "idle" };
  var pcPills = { timer: null, polling: false, signature: "" };

  function pcPillsDeclared() {
    return pcState.consoles.some(function (manifest) {
      return Array.isArray(manifest.pills) && manifest.pills.length > 0;
    });
  }

  function pcSchedulePills(delay) {
    if (pcPills.timer) clearTimeout(pcPills.timer);
    pcPills.timer = null;
    if (!pcPillsDeclared()) {
      pcRenderPills([]);
      return;
    }
    pcPills.timer = setTimeout(pcPollPills, delay);
  }

  async function pcPollPills() {
    pcPills.timer = null;
    // Hidden: no tick is booked; the visibilitychange handler books the next.
    if (document.hidden || pcPills.polling) return;
    pcPills.polling = true;
    try {
      var data = await apiFetch("/api/plugin-consoles/pills");
      pcRenderPills(Array.isArray(data && data.pills) ? data.pills : []);
    } catch (_err) {
      // The bar keeps the pills it has; the next tick asks again.
    }
    pcPills.polling = false;
    if (!document.hidden) pcSchedulePills(PC_PILLS_POLL_MS);
  }

  function pcPillSpan(className, text) {
    var span = document.createElement("span");
    span.className = className;
    if (text !== null) span.textContent = text;
    return span;
  }

  function pcRenderPills(pills) {
    var host = $("topbar-plugin-pills");
    if (!host) return;
    var signature = JSON.stringify(pills);
    if (signature === pcPills.signature) return;
    pcPills.signature = signature;
    host.textContent = "";
    var seen = {};
    pills.forEach(function (pill) {
      var button = document.createElement("button");
      button.type = "button";
      // A console's further pills fold away first on a narrow bar (shell.css).
      button.className = "topbar-card-bridge topbar-plugin-pill" + (seen[pill.console] ? " topbar-plugin-pill--more" : "");
      seen[pill.console] = true;
      button.setAttribute("data-state", PC_PILL_TONES[pill.state] || "idle");
      button.title = pill.title + " - " + pill.label + ": " + pill.value + ". Opens the console.";
      button.setAttribute("aria-label", button.title);
      var dot = pcPillSpan("topbar-card-bridge-dot", null);
      dot.setAttribute("aria-hidden", "true");
      button.appendChild(dot);
      button.appendChild(pcPillSpan("topbar-card-bridge-label", pill.label));
      button.appendChild(pcPillSpan("topbar-card-bridge-value", pill.value));
      button.addEventListener("click", function () {
        ccOpenInspectView("plugin_console", PC_LEAF_PREFIX + pill.console);
      });
      host.appendChild(button);
    });
    host.hidden = pills.length === 0;
  }
