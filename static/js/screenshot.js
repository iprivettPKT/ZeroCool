/* ZeroCool — capture terminal output as a PNG and save it as a finding.
 * Adds a 📷 button to every terminal header; on click it renders the output
 * pane with html2canvas and opens a dialog to file a finding with the image.
 */
(function () {
  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  ready(function () {
    if (typeof html2canvas === "undefined") return;

    // --- build the dialog once ---
    const modal = document.createElement("div");
    modal.id = "ss-modal";
    modal.className = "ss-modal hidden";
    modal.innerHTML =
      '<div class="ss-dialog">' +
      '  <div class="ss-head"><span>Save terminal screenshot as finding</span><button class="btn-icon" data-x>✕</button></div>' +
      '  <div class="ss-body">' +
      '    <img class="ss-preview" data-preview alt="screenshot preview">' +
      '    <label>Title <input type="text" data-title placeholder="e.g. Kerberoastable service account"></label>' +
      '    <div class="ss-row">' +
      '      <label>Severity <select data-sev><option>Critical</option><option>High</option><option selected>Medium</option><option>Low</option><option>Info</option></select></label>' +
      '      <label>Host <input type="text" data-host></label>' +
      '      <label>Port <input type="text" data-port></label>' +
      '    </div>' +
      '    <label>Notes <textarea rows="2" data-desc></textarea></label>' +
      '    <div class="ss-actions"><button class="btn primary" data-save>Save finding</button>' +
      '      <a class="btn ghost" data-dl download="terminal.png">Download PNG</a>' +
      '      <span class="muted small" data-msg></span></div>' +
      '  </div></div>';
    document.body.appendChild(modal);
    const q = (s) => modal.querySelector(s);
    let currentImage = "";

    const close = () => modal.classList.add("hidden");
    q("[data-x]").onclick = close;
    modal.addEventListener("click", (e) => { if (e.target === modal) close(); });

    function openDialog(dataUrl, cmd) {
      currentImage = dataUrl;
      q("[data-preview]").src = dataUrl;
      q("[data-dl]").href = dataUrl;
      q("[data-title]").value = "";
      q("[data-desc]").value = cmd ? ("Command: " + cmd) : "";
      q("[data-msg]").textContent = "";
      modal.classList.remove("hidden");
      q("[data-title]").focus();
    }

    q("[data-save]").addEventListener("click", async () => {
      const title = q("[data-title]").value.trim();
      const msg = q("[data-msg]");
      if (!title) { msg.textContent = "title required"; return; }
      msg.textContent = "saving…";
      try {
        const r = await fetch("/loot/finding/screenshot", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            title, severity: q("[data-sev]").value, host: q("[data-host]").value,
            port: q("[data-port]").value, description: q("[data-desc]").value,
            evidence: q("[data-desc]").value, image: currentImage,
          }),
        });
        const d = await r.json();
        if (r.ok) { msg.textContent = "saved ✓ — finding " + d.id; setTimeout(close, 1300); }
        else { msg.textContent = "error: " + (d.error || r.status); }
      } catch (e) { msg.textContent = "error"; }
    });

    // --- attach a capture button to each terminal present on the page ---
    async function capture(termEl, out, btn) {
      btn.disabled = true;
      // Temporarily expand the pane so the full (scrolled) output is captured.
      const pm = out.style.maxHeight, po = out.style.overflow;
      out.style.maxHeight = "none"; out.style.overflow = "visible";
      try {
        const canvas = await html2canvas(out, { backgroundColor: "#050805", logging: false });
        const cmd = (termEl.querySelector("[data-term-cmd]") || {}).textContent || "";
        openDialog(canvas.toDataURL("image/png"), cmd);
      } catch (e) {
        alert("screenshot failed: " + e);
      } finally {
        out.style.maxHeight = pm; out.style.overflow = po; btn.disabled = false;
      }
    }

    document.querySelectorAll(".terminal").forEach((termEl) => {
      const head = termEl.querySelector(".term-head");
      const out = termEl.querySelector("[data-term-output]");
      if (!head || !out || head.querySelector(".ss-btn")) return;
      const btn = document.createElement("button");
      btn.className = "ss-btn";
      btn.title = "Screenshot → save as finding";
      btn.textContent = "📷";
      head.appendChild(btn);
      btn.addEventListener("click", () => capture(termEl, out, btn));
    });
  });
})();
