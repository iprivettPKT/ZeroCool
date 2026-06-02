/* ZCPersist — lightweight client-side state persistence.
 *
 * - save/load/remove: namespaced (per page path) key/value via localStorage.
 * - autoForm(): auto-save & restore every form control inside a root (default
 *   .content), keyed by id/name. Restored values dispatch input/change so each
 *   page's own logic (command previews etc.) re-runs.
 *
 * Opt out by putting data-no-persist on an element or any ancestor. Password
 * fields are never persisted.
 */
window.ZCPersist = (function () {
  const PREFIX = "zc:";
  function k(key) { return PREFIX + location.pathname + "|" + key; }
  function save(key, val) { try { localStorage.setItem(k(key), JSON.stringify(val)); } catch (e) {} }
  function load(key, dflt) {
    try { const s = localStorage.getItem(k(key)); return s == null ? dflt : JSON.parse(s); }
    catch (e) { return dflt; }
  }
  function remove(key) { try { localStorage.removeItem(k(key)); } catch (e) {} }

  function skip(el) {
    return !!el.closest("[data-no-persist]") ||
      el.type === "password" || el.type === "file" ||
      el.type === "submit" || el.type === "button";
  }
  function fkey(el) {
    const base = el.id || el.name;
    if (!base) return null;
    return "f:" + base + (el.type === "radio" ? ":" + el.value : "");
  }

  function autoForm(root) {
    root = root || document.querySelector(".content");
    if (!root) return;
    root.querySelectorAll("input, textarea, select").forEach((el) => {
      if (skip(el)) return;
      const fk = fkey(el);
      if (!fk) return;
      const saved = load(fk, undefined);
      if (saved !== undefined) {
        try {
          if (el.type === "checkbox" || el.type === "radio") el.checked = !!saved;
          else el.value = saved;
          const evt = (el.tagName === "SELECT" || el.type === "checkbox" || el.type === "radio") ? "change" : "input";
          el.dispatchEvent(new Event(evt, { bubbles: true }));
        } catch (e) {}
      }
      const handler = () => {
        if (el.type === "checkbox" || el.type === "radio") save(fk, el.checked);
        else save(fk, el.value);
      };
      el.addEventListener("input", handler);
      el.addEventListener("change", handler);
    });
  }

  return { save, load, remove, autoForm, key: k };
})();
