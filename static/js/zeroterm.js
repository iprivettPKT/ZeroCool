/* ZeroTerm — reusable live terminal pane.
 *
 * Attach to a DOM subtree that contains:
 *   [data-term-output]  <pre> where output lines go
 *   [data-term-status]  status label element
 *   [data-term-cmd]     element showing the running command
 *
 * Returns a controller: { run(command, cwd), kill(), clear(), onState(fn), job() }
 * It talks to the runner endpoints exposed by app.py.
 */
window.ZeroTerm = (function () {
  const RUN_URL = "/terminal/run";
  const STREAM_URL = "/terminal/stream/";
  const KILL_URL = "/terminal/kill/";

  function attach(root, opts) {
    opts = opts || {};
    const clearOnRun = opts.clearOnRun !== false;  // default: clear each run
    const out = root.querySelector("[data-term-output]");
    const statusEl = root.querySelector("[data-term-status]");
    const cmdLabel = root.querySelector("[data-term-cmd]");
    let es = null;
    let currentJob = null;
    let stateCb = null;
    let runCb = null;

    function setStatus(s) {
      if (statusEl) {
        statusEl.textContent = s;
        statusEl.className = "term-status status-" + s;
      }
      if (stateCb) stateCb(s);
    }

    function append(text, cls) {
      const span = document.createElement("span");
      span.className = "ln" + (cls ? " " + cls : "");
      span.textContent = text + "\n";
      out.appendChild(span);
      out.scrollTop = out.scrollHeight;
    }

    function clear() {
      out.textContent = "";
    }

    function finish(status) {
      setStatus(status);
      if (es) { es.close(); es = null; }
      currentJob = null;
    }

    async function run(command, cwd) {
      command = (command || "").trim();
      if (!command) return;
      if (es) { es.close(); es = null; }
      if (clearOnRun) clear();
      append("$ " + command, "meta");
      setStatus("running");
      if (cmdLabel) cmdLabel.textContent = command;

      let resp;
      try {
        resp = await fetch(RUN_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ command: command, cwd: cwd || "" }),
        });
      } catch (e) {
        append("[zerocool] request failed: " + e, "meta");
        finish("failed");
        return;
      }
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        append("[zerocool] " + (err.error || "HTTP " + resp.status), "meta");
        finish("failed");
        return;
      }
      const job = await resp.json();
      currentJob = job.id;
      if (runCb) runCb(job.id, command);

      es = new EventSource(STREAM_URL + job.id);
      es.onmessage = (ev) => {
        const m = JSON.parse(ev.data);
        if (m.type === "line") {
          append(m.text, m.stream === "stderr" ? "err" : null);
        } else if (m.type === "done") {
          append("[exit " + m.exit_code + " · " + m.status + "]", "meta");
          finish(m.status);
        } else if (m.type === "error") {
          append("[zerocool] " + m.message, "meta");
          finish("failed");
        }
      };
      es.onerror = () => { if (es) { es.close(); es = null; } };
    }

    async function kill() {
      if (currentJob) {
        await fetch(KILL_URL + currentJob, { method: "POST" }).catch(() => {});
      }
    }

    // Re-render a previously-run job (from the runner's saved record) and, if it
    // is still running, reconnect to its live stream. Used to restore drawer
    // tabs across page navigations.
    async function attachJob(jobId) {
      let rec;
      try {
        const resp = await fetch("/terminal/job/" + jobId);
        if (!resp.ok) return;
        rec = await resp.json();
      } catch (e) { return; }
      if (!rec || rec.error) return;
      append("$ " + rec.command, "meta");
      (rec.lines || []).forEach((ln) => append(ln.text, ln.stream === "stderr" ? "err" : null));
      currentJob = jobId;
      const live = rec.status === "running" || rec.status === "pending";
      if (live) {
        setStatus("running");
        const cursor = rec.total_lines != null ? rec.total_lines : (rec.lines || []).length;
        es = new EventSource(STREAM_URL + jobId + "?since=" + cursor);
        es.onmessage = (ev) => {
          const m = JSON.parse(ev.data);
          if (m.type === "line") append(m.text, m.stream === "stderr" ? "err" : null);
          else if (m.type === "done") { append("[exit " + m.exit_code + " · " + m.status + "]", "meta"); finish(m.status); }
        };
        es.onerror = () => { if (es) { es.close(); es = null; } };
      } else {
        append("[exit " + rec.exit_code + " · " + rec.status + "]", "meta");
        setStatus(rec.status);
      }
    }

    return {
      run: run,
      kill: kill,
      clear: clear,
      attachJob: attachJob,
      onState: (fn) => { stateCb = fn; },
      onRun: (fn) => { runCb = fn; },
      job: () => currentJob,
    };
  }

  return { attach: attach };
})();
