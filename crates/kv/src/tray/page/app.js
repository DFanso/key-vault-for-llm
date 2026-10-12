// kv's window. The tray sends messages through kv.receive; the page sends
// its own with window.ipc.postMessage. All text from the tray, much of it
// written by agents, goes into the page as text nodes, never as markup.
"use strict";

(() => {
  const $ = (id) => document.getElementById(id);

  const page = {
    locked: true,
    device: null,
    waiting: false,
    overview: null,
    tab: "approvals",
    // What each list was last drawn from, to redraw only on a change.
    drawn: { cards: "", requests: "", handles: "" },
    form: null,
    removing: null,
  };

  function send(message) {
    window.ipc.postMessage(JSON.stringify(message));
  }

  // An element with text and children; strings become text nodes.
  function el(tag, className, ...children) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    for (const child of children) {
      if (child === null || child === undefined) continue;
      node.append(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  function button(label, onClick, className) {
    const node = el("button", className || null, label);
    node.type = "button";
    node.addEventListener("click", onClick);
    return node;
  }

  function show(node, shown) {
    node.hidden = !shown;
  }

  // "7h 52m", "3m", "40s".
  function duration(secs) {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m`;
    return `${secs}s`;
  }

  // Messages from the tray.

  function receive(message) {
    switch (message.type) {
      case "state":
        page.locked = message.locked;
        page.device = message.device;
        page.waiting = message.waiting_for_device;
        page.overview = message.overview;
        if (page.locked) {
          closeForm(false);
          closeConfirm();
          // Whatever it said belonged to the session that just ended.
          $("app-message").textContent = "";
          show($("app-message"), false);
        }
        draw();
        break;
      case "show":
        page.tab = message.tab;
        draw();
        break;
      case "form":
        openForm(message.view);
        break;
      case "form_error":
        $("form-error").textContent = message.message;
        break;
      case "form_done":
        closeForm(false);
        break;
      case "audit":
        drawAudit(message.entries);
        break;
      case "message":
        say(message.text, message.request);
        break;
    }
  }

  function say(text, request) {
    if (request !== null && request !== undefined) {
      const card = document.querySelector(`.card[data-id="${Number(request)}"] .message`);
      if (card) {
        card.textContent = text;
        return;
      }
    }
    if (page.locked) {
      $("unlock-message").textContent = text;
    } else {
      const note = $("app-message");
      note.textContent = text;
      show(note, true);
    }
  }

  // Drawing.

  function draw() {
    show($("unlock"), page.locked);
    show($("app"), !page.locked);
    if (page.locked) {
      drawUnlock();
    } else {
      drawApp();
    }
  }

  function drawUnlock() {
    const waiting = page.waiting && page.device;
    const waitingNote = $("unlock-waiting");
    waitingNote.textContent = waiting ? `Waiting for ${page.device}…` : "";
    show(waitingNote, waiting);
    const form = $("unlock-form");
    const wasHidden = form.hidden;
    show(form, !waiting);
    const useDevice = $("use-device");
    useDevice.textContent = page.device ? `Use ${page.device}` : "";
    show(useDevice, Boolean(page.device) && !waiting);
    if (wasHidden && !waiting) $("passphrase").focus();
    page.drawn = { cards: "", requests: "", handles: "" };
  }

  function drawApp() {
    $("unlock-message").textContent = "";
    const overview = page.overview;
    const secs = overview && overview.status.locks_in_secs;
    $("locks-in").textContent =
      secs === null || secs === undefined ? "Unlocked" : `Unlocked · locks in ${duration(secs)}`;
    const waiting = overview ? overview.approvals.length : 0;
    for (const tab of document.querySelectorAll("nav button")) {
      const name = tab.dataset.tab;
      tab.setAttribute("aria-selected", String(name === page.tab));
      if (name === "approvals") {
        tab.textContent = waiting > 0 ? `Approvals (${waiting})` : "Approvals";
      }
    }
    for (const name of ["approvals", "handles", "audit"]) {
      show($(name), name === page.tab);
    }
    if (!overview) return;
    drawCards(overview.approvals);
    drawRequests(overview.handle_requests);
    drawHandles(overview.handles, overview.role_warnings || {});
  }

  function drawCards(approvals) {
    show($("no-approvals"), approvals.length === 0);
    // The countdowns change every second; the cards only when requests come
    // or go, so a button the user is about to press stays put.
    const shape = JSON.stringify(approvals.map((a) => ({ ...a, expires_in_secs: 0 })));
    if (shape !== page.drawn.cards) {
      page.drawn.cards = shape;
      const kept = new Map();
      for (const card of $("cards").children) kept.set(card.dataset.id, card);
      const cards = approvals.map((approval) => kept.get(String(approval.id)) || card(approval));
      $("cards").replaceChildren(...cards);
    }
    for (const approval of approvals) {
      const expires = document.querySelector(`.card[data-id="${Number(approval.id)}"] .expires`);
      if (expires) expires.textContent = `Expires in ${approval.expires_in_secs}s`;
    }
  }

  function card(approval) {
    const handles = approval.handles.join(", ");
    const decide = (verdict) => () => send({ type: "decide", id: approval.id, verdict });
    const buttons = el(
      "div",
      "buttons",
      button("Allow once", decide("allow_once"), "primary"),
      approval.can_grant ? button("Allow for this session", decide("allow_session")) : null,
      button("Deny", decide("deny")),
      button(`Deny and block ${handles}`, decide("deny_always"), "danger"),
    );
    const node = el(
      "div",
      "card",
      el("div", "title", `${approval.client || "agent"} · ${approval.tool} · ${handles}`),
      el("div", "detail", approval.detail),
      approval.cwd ? el("div", "muted", `in ${approval.cwd}`) : null,
      el("div", "muted expires", `Expires in ${approval.expires_in_secs}s`),
      buttons,
      el("p", "message"),
    );
    node.dataset.id = String(approval.id);
    return node;
  }

  function drawRequests(requests) {
    const shape = JSON.stringify(requests);
    if (shape === page.drawn.requests) return;
    page.drawn.requests = shape;
    const cards = requests.map((requested) => {
      const r = requested.request;
      const allows = r.kind === "env" ? r.env_vars : r.allowed_hosts;
      return el(
        "div",
        "card",
        el("div", "title", `${requested.client || "An agent"} asked for ${r.name} (${r.kind})`),
        r.description ? el("div", null, r.description) : null,
        el("div", "muted", `Why: ${r.reason}`),
        allows.length > 0 ? el("div", "muted", allows.join(", ")) : null,
        el(
          "div",
          "buttons",
          button("Fill in", () => openRequest({ kind: "request", id: requested.id }), "primary"),
          button("Dismiss", () => send({ type: "dismiss", id: requested.id })),
        ),
      );
    });
    $("requests").replaceChildren(...cards);
  }

  function drawHandles(handles, warnings) {
    const shape = JSON.stringify([handles, warnings]);
    if (shape === page.drawn.handles) return;
    page.drawn.handles = shape;
    show($("no-handles"), handles.length === 0);
    show($("handle-table"), handles.length > 0);
    const rows = handles.map((handle) => {
      const allows = {
        http: handle.allowed_hosts,
        env: handle.allowed_cmds,
      }[handle.kind];
      const name = el("td", null, el("div", "title", handle.name));
      if (handle.description) name.append(el("div", "muted", handle.description));
      if (warnings[handle.name]) name.append(el("div", "warning", warnings[handle.name]));
      return el(
        "tr",
        null,
        name,
        el("td", "short", handle.kind),
        el("td", "short", handle.read_only ? `${handle.mode}, read only` : handle.mode),
        el("td", "long", allows ? allows.join(", ") : ""),
        el(
          "td",
          "actions",
          button("Edit", () => openRequest({ kind: "edit", name: handle.name })),
          button("Policy", () => openRequest({ kind: "policy", name: handle.name })),
          button("Remove", () => confirmRemove(handle.name), "danger"),
        ),
      );
    });
    $("handle-rows").replaceChildren(...rows);
  }

  function drawAudit(entries) {
    show($("no-audit"), entries.length === 0);
    show($("audit-table"), entries.length > 0);
    const rows = entries.map((e) =>
      el(
        "tr",
        null,
        // `2026-10-08T12:03:04.123Z` → `2026-10-08 12:03:04`, as kv tui shows it
        el("td", "short muted", e.ts.slice(0, 19).replace("T", " ")),
        el("td", "short", e.action),
        el("td", null, e.handle || ""),
        el("td", "short", e.decision || ""),
        el("td", "short", e.outcome),
        el("td", "long", e.summary || ""),
      ),
    );
    $("audit-rows").replaceChildren(...rows);
  }

  // Forms, drawn from the tray's description of them. The tray checks what
  // is typed; the page only shows and hides fields as the TUI does.

  function openRequest(form) {
    send({ type: "open_form", form });
  }

  function openForm(view) {
    page.form = view;
    $("form-title").textContent = view.title;
    $("form-error").textContent = "";
    const fields = view.fields.map(field);
    $("form-fields").replaceChildren(...fields);
    applyConditions();
    const dialog = $("form-dialog");
    if (!dialog.open) dialog.showModal();
    const focus = view.focus && $(`field-${view.focus}`);
    if (focus) focus.focus();
  }

  function field(spec) {
    const id = `field-${spec.key}`;
    let input;
    switch (spec.kind) {
      case "choice":
        input = el("select");
        for (const option of spec.options) {
          const node = el("option", null, option);
          node.value = option;
          input.append(node);
        }
        input.value = spec.value;
        input.addEventListener("change", applyConditions);
        break;
      case "pairs":
        input = pairs(id);
        break;
      case "secret":
        input = el("input");
        input.type = "password";
        input.autocomplete = "off";
        break;
      default:
        input = el("input");
        input.type = "text";
        input.value = spec.value;
        input.spellcheck = false;
    }
    if (spec.kind !== "pairs") input.id = id;
    input.dataset.key = spec.key;
    const label = el("label", null, spec.label);
    label.htmlFor = id;
    const node = el("div", "field", label, input, spec.hint ? el("p", "hint", spec.hint) : null);
    node.dataset.key = spec.key;
    node.dataset.kind = spec.kind;
    return node;
  }

  // Variables: a name and a value per row. The value is a password field,
  // like every other secret.
  function pairs(id) {
    const rows = el("div", "pairs");
    const add = button("Add variable", () => {
      rows.insertBefore(pair(null), add);
      rows.querySelector(".pair:last-of-type .pair-name").focus();
    });
    rows.append(pair(id), add);
    return rows;
  }

  function pair(id) {
    const name = el("input", "pair-name");
    name.type = "text";
    name.placeholder = "NAME";
    name.spellcheck = false;
    name.autocomplete = "off";
    if (id) name.id = id;
    const value = el("input", "pair-value");
    value.type = "password";
    value.placeholder = "value";
    value.autocomplete = "off";
    const row = el("div", "pair", name, value);
    row.append(button("Remove", () => row.remove()));
    return row;
  }

  // The rows as `NAME=value` lines, as the tray reads them. Empty rows are
  // left out.
  function pairLines(node) {
    const lines = [];
    for (const row of node.querySelectorAll(".pair")) {
      const name = row.querySelector(".pair-name").value;
      const value = row.querySelector(".pair-value").value;
      if (name || value) lines.push(`${name}=${value}`);
    }
    return lines.join("\n");
  }

  // A field shows while every choice in its chain has one of its options;
  // the tray sends the whole chain, so a field hides with the one it hangs
  // from.
  function applyConditions() {
    if (!page.form) return;
    for (const spec of page.form.fields) {
      const node = document.querySelector(`.field[data-key="${CSS.escape(spec.key)}"]`);
      if (!node) continue;
      show(
        node,
        spec.when.every((when) => {
          const other = $(`field-${when.key}`);
          return other !== null && when.options.includes(other.value);
        }),
      );
    }
  }

  function submitForm(event) {
    event.preventDefault();
    if (!page.form) return;
    const values = {};
    for (const node of $("form-fields").children) {
      if (node.hidden) continue;
      if (node.dataset.kind === "pairs") {
        values[node.dataset.key] = pairLines(node);
        continue;
      }
      const input = node.querySelector("input, select");
      values[input.dataset.key] = input.value;
    }
    $("form-error").textContent = "";
    send({ type: "submit_form", values });
  }

  // Closes the form and wipes what was typed. `tell` says the tray does not
  // know yet.
  function closeForm(tell) {
    const dialog = $("form-dialog");
    if (!page.form && !dialog.open) return;
    page.form = null;
    $("form").reset();
    $("form-fields").replaceChildren();
    if (dialog.open) dialog.close();
    if (tell) send({ type: "close_form" });
  }

  function confirmRemove(name) {
    page.removing = name;
    $("confirm-text").textContent = `Remove ${name}? Agents lose it at once, and its secret is gone.`;
    $("confirm-dialog").showModal();
  }

  function closeConfirm() {
    page.removing = null;
    const dialog = $("confirm-dialog");
    if (dialog.open) dialog.close();
  }

  // Wiring.

  function start() {
    $("unlock-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const input = $("passphrase");
      const passphrase = input.value;
      input.value = "";
      $("unlock-message").textContent = "";
      if (passphrase) send({ type: "unlock", passphrase });
    });
    $("use-device").addEventListener("click", () => {
      $("unlock-message").textContent = "";
      send({ type: "device_unlock" });
    });
    $("lock").addEventListener("click", () => send({ type: "lock" }));
    $("add").addEventListener("click", () => openRequest({ kind: "new" }));
    for (const tab of document.querySelectorAll("nav button")) {
      tab.addEventListener("click", () => {
        page.tab = tab.dataset.tab;
        $("app-message").hidden = true;
        send({ type: "tab", tab: page.tab });
        draw();
      });
    }
    $("form").addEventListener("submit", submitForm);
    $("form-cancel").addEventListener("click", () => closeForm(true));
    // Esc on an open form.
    $("form-dialog").addEventListener("cancel", (event) => {
      event.preventDefault();
      closeForm(true);
    });
    $("confirm").addEventListener("submit", (event) => {
      event.preventDefault();
      if (page.removing) send({ type: "remove", name: page.removing });
      closeConfirm();
    });
    $("confirm-cancel").addEventListener("click", closeConfirm);
    $("confirm-dialog").addEventListener("cancel", (event) => {
      event.preventDefault();
      closeConfirm();
    });
    draw();
    send({ type: "ready" });
  }

  window.kv = Object.freeze({ receive });
  start();
})();
