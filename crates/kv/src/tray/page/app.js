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
    drawn: { cards: "", requests: "", handles: "", shares: "" },
    form: null,
    // What the confirm dialog's button sends.
    confirming: null,
    revealTimer: null,
    // The share dialog's step, while it is open, and whether the tray is
    // working on it.
    share: null,
    shareBusy: false,
  };

  const REVEAL_SECS = 60;

  // The keys that copy a selection here.
  const COPY_KEYS = /Mac/.test(navigator.platform) ? "⌘C" : "Ctrl+C";

  // The share dialog's three steps. The tray checks what is typed; the page
  // only shows the fields each step needs.
  const SHARE_STEPS = {
    request: {
      title: "Request a secret",
      about:
        "kv makes a code for you to send to the person who has the secret. It holds only a public " +
        "key, so any chat can carry it.",
      submit: "Make code",
      note: [
        "What you need",
        "Optional, e.g. the staging database URL. It goes in the code, which anyone in the chat can read.",
      ],
    },
    send: {
      title: "Send a secret",
      about:
        "Paste the request code they sent you and pick a handle. kv seals its value so that only " +
        "the vault that made the code can open it.",
      submit: "Seal",
      code: ["Their request code", "kv-request:v1:…"],
      note: ["Note", "Optional; they see it with the share."],
      name: ["Name to suggest", "Optional; blank suggests the handle's own name."],
    },
    receive: {
      title: "Receive a share",
      about:
        "Paste the share they sent back. kv opens it with the key of your open request and saves it " +
        "as a new handle in ask mode.",
      submit: "Save",
      code: ["Their share", "kv-share:v1:…"],
      name: ["Save as", "Optional; blank uses the name they suggested."],
    },
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
          closeReveal();
          closeShare();
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
      case "revealed":
        openReveal(message.handle, message.fields);
        break;
      case "shared":
        shareDone(message.result);
        break;
      case "share_error":
        shareBusy(false);
        $("share-error").textContent = message.message;
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
    page.drawn = { cards: "", requests: "", handles: "", shares: "" };
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
    for (const name of ["approvals", "handles", "shares", "audit"]) {
      show($(name), name === page.tab);
    }
    if (!overview) return;
    drawCards(overview.approvals);
    drawRequests(overview.handle_requests);
    drawHandles(overview.handles, overview.role_warnings || {});
    drawShares(overview.shares || { requests: [], received: [], sent: [] }, overview.handles);
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

  // A Unix time as the user's local date and time.
  function when(secs) {
    return new Date(secs * 1000).toLocaleString();
  }

  function drawShares(shares, handles) {
    const shape = JSON.stringify([shares, handles.map((h) => h.name)]);
    if (shape === page.drawn.shares) return;
    page.drawn.shares = shape;

    show($("no-share-requests"), shares.requests.length === 0);
    const requests = shares.requests.map((request) => {
      const title = request.note
        ? `Request ${request.safety_code} · ${request.note}`
        : `Request ${request.safety_code}`;
      const status = request.expired
        ? `Expired ${when(request.expires_at)}`
        : `Opened ${when(request.created_at)} · open until ${when(request.expires_at)}`;
      const code = el("div", "detail code", request.code);
      return el(
        "div",
        "card",
        el("div", "title", title),
        el("div", "muted", status),
        code,
        el(
          "div",
          "buttons",
          request.expired ? null : button("Copy code", (event) => copyText(code, event.currentTarget)),
          button(
            request.expired ? "Remove" : "Cancel request",
            () =>
              confirmThen(
                `Cancel request ${request.safety_code}? A share sealed to it can no longer be opened.`,
                "Cancel request",
                { type: "forget", id: request.id },
              ),
            "danger",
          ),
        ),
      );
    });
    $("share-requests").replaceChildren(...requests);

    const names = new Set(handles.map((h) => h.name));
    const forget = (id, what) =>
      button("Forget", () => confirmThen(`Forget ${what}? This only clears the record.`, "Forget", { type: "forget", id }));

    show($("no-received"), shares.received.length === 0);
    show($("received-table"), shares.received.length > 0);
    $("received-rows").replaceChildren(
      ...shares.received
        .slice()
        .reverse()
        .map((r) => {
          const name = el("td", null, el("div", "title", r.handle));
          if (r.note) name.append(el("div", "muted", r.note));
          if (!names.has(r.handle)) {
            name.append(el("div", "muted", "removed since"));
          } else if (!r.viewable) {
            name.append(el("div", "muted", "changed since, so kv no longer shows it"));
          }
          return el(
            "tr",
            null,
            name,
            el("td", "short", r.kind),
            el("td", null, r.from || "not given"),
            el("td", "short code", r.safety_code),
            el("td", "short muted", when(r.received_at)),
            el(
              "td",
              "actions",
              r.viewable ? button("View", () => send({ type: "reveal", handle: r.handle })) : null,
              forget(r.id, `the record of ${r.handle}`),
            ),
          );
        }),
    );

    show($("no-sent"), shares.sent.length === 0);
    show($("sent-table"), shares.sent.length > 0);
    $("sent-rows").replaceChildren(
      ...shares.sent
        .slice()
        .reverse()
        .map((s) => {
          const name = el("td", null, el("div", "title", s.handle));
          if (s.note) name.append(el("div", "muted", s.note));
          return el(
            "tr",
            null,
            name,
            el("td", "short", s.kind),
            el("td", null, s.to || "not given"),
            el("td", "short code", s.safety_code),
            el("td", "short muted", when(s.sent_at)),
            el("td", "actions", forget(s.id, `the record of sending ${s.handle}`)),
          );
        }),
    );
  }

  // A received value, drawn as text the user can select, and wiped when the
  // dialog closes, the timer runs out or the vault locks.
  function openReveal(handle, fields) {
    $("reveal-title").textContent = handle;
    $("reveal-fields").replaceChildren(
      ...fields.map((f) => el("div", "field", el("div", "muted", f.label), el("div", "detail code secret-value", f.value))),
    );
    const dialog = $("reveal-dialog");
    if (!dialog.open) dialog.showModal();
    clearTimeout(page.revealTimer);
    page.revealTimer = setTimeout(closeReveal, REVEAL_SECS * 1000);
  }

  function closeReveal() {
    clearTimeout(page.revealTimer);
    page.revealTimer = null;
    $("reveal-fields").replaceChildren();
    $("reveal-title").textContent = "";
    const dialog = $("reveal-dialog");
    if (dialog.open) dialog.close();
  }

  // Copies `node`'s text. The copy command needs the text selected; where
  // it fails, the clipboard API may still work, and failing that the text
  // stays selected for the user's own keys.
  function copyText(node, label) {
    const text = node.textContent;
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(node);
    selection.removeAllRanges();
    selection.addRange(range);
    let copied = false;
    try {
      copied = document.execCommand("copy");
    } catch (_) {
      copied = false;
    }
    const tell = (done) => {
      if (done) selection.removeAllRanges();
      const was = label.dataset.label || label.textContent;
      label.dataset.label = was;
      label.textContent = done ? "Copied" : `Selected: press ${COPY_KEYS}`;
      clearTimeout(label.copyTimer);
      label.copyTimer = setTimeout(() => {
        label.textContent = was;
      }, 2000);
    };
    if (copied || !navigator.clipboard) {
      tell(copied);
      return;
    }
    navigator.clipboard.writeText(text).then(
      () => tell(true),
      () => tell(false),
    );
  }

  // The share dialog: what to type for `step`, then what came of it.

  function openShare(step) {
    const spec = SHARE_STEPS[step];
    page.share = step;
    $("share-form").reset();
    $("share-title").textContent = spec.title;
    $("share-about").textContent = spec.about;
    $("share-submit").textContent = spec.submit;
    for (const node of $("share-ask").querySelectorAll(".field")) {
      show(node, node.dataset.for.split(" ").includes(step));
    }
    if (spec.code) {
      $("share-code-label").textContent = spec.code[0];
      $("share-code").placeholder = spec.code[1];
    }
    if (spec.note) {
      $("share-note-label").textContent = spec.note[0];
      $("share-note-hint").textContent = spec.note[1];
    }
    if (spec.name) {
      $("share-name-label").textContent = spec.name[0];
      $("share-name-hint").textContent = spec.name[1];
    }
    if (step === "send") fillShareHandles();
    shareResult(false);
    shareBusy(false);
    $("share-error").textContent = "";
    const dialog = $("share-dialog");
    if (!dialog.open) dialog.showModal();
    const first = [...$("share-ask").querySelectorAll(".field")].find((node) => !node.hidden);
    if (first) first.querySelector("input, select").focus();
  }

  // Every handle, the ones set to deny greyed out: kv will not share those.
  function fillShareHandles() {
    const handles = (page.overview && page.overview.handles) || [];
    const options = handles.map((handle) => {
      const deny = handle.mode === "deny";
      const option = el("option", null, deny ? `${handle.name} (${handle.kind}) · set to deny` : `${handle.name} (${handle.kind})`);
      option.value = handle.name;
      option.disabled = deny;
      return option;
    });
    $("share-handle").replaceChildren(...options);
    const first = handles.find((handle) => handle.mode !== "deny");
    $("share-handle").value = first ? first.name : "";
  }

  function submitShare(event) {
    event.preventDefault();
    if (!page.share || page.shareBusy || !$("share-result").hidden) return;
    const value = (id) => $(id).value;
    let message;
    switch (page.share) {
      case "request":
        message = { type: "request_share", note: value("share-note"), from: value("share-from") };
        break;
      case "send":
        if (!value("share-handle")) {
          $("share-error").textContent = "Pick a handle to send; add one on the Handles tab first.";
          return;
        }
        message = {
          type: "send_share",
          request: value("share-code"),
          handle: value("share-handle"),
          name: value("share-name"),
          from: value("share-from"),
          note: value("share-note"),
        };
        break;
      case "receive":
        message = { type: "receive_share", share: value("share-code"), name: value("share-name") };
        break;
      default:
        return;
    }
    $("share-error").textContent = "";
    shareBusy(true);
    send(message);
  }

  function shareBusy(busy) {
    page.shareBusy = busy;
    $("share-submit").disabled = busy;
  }

  function shareDone(result) {
    shareBusy(false);
    if (!page.share) return;
    let about;
    let output = "";
    let safety;
    switch (result.step) {
      case "requested":
        about =
          "Send this code to the person who has the secret. It also waits under Waiting for a share " +
          "until their share comes back; then use Receive a share.";
        output = result.code;
        safety =
          `Safety code ${result.safety_code}. They see it when they send. For anything sensitive, ` +
          "check over a call that theirs matches before you use what arrives.";
        break;
      case "sealed":
        about =
          `Send this back to ${result.to || "them"}. Only the vault that made the request can open ` +
          "it. kv does not keep this text, so copy it before you close.";
        if (result.asked_for) about += ` They asked for: ${result.asked_for}`;
        output = result.share;
        safety =
          `Safety code ${result.safety_code}. Anyone in the chat could have posted that request: ` +
          "for anything sensitive, check over a call that their request shows the same code before " +
          "you send this.";
        break;
      case "received":
        about =
          `Saved as ${result.handle} (${result.kind}). ` +
          (result.from ? `It says it is from ${result.from}; nothing checks that. ` : "It gives no sender. ") +
          "It starts in ask mode, so each use waits for you; add what it needs with Policy on the " +
          "Handles tab.";
        safety =
          `Safety code ${result.safety_code}. For anything sensitive, check over a call that the ` +
          "sender saw the same code.";
        break;
      default:
        return;
    }
    $("share-result-about").textContent = about;
    $("share-output").textContent = output;
    show($("share-output"), Boolean(output));
    $("share-safety").textContent = safety;
    shareResult(true);
    show($("share-copy"), Boolean(output));
    if (output) $("share-copy").focus();
    else $("share-cancel").focus();
  }

  function shareResult(shown) {
    show($("share-ask"), !shown);
    show($("share-about"), !shown);
    show($("share-result"), shown);
    show($("share-submit"), !shown);
    show($("share-copy"), false);
    $("share-cancel").textContent = shown ? "Done" : "Cancel";
  }

  // Closes the share dialog and drops what was typed and shown.
  function closeShare() {
    page.share = null;
    shareBusy(false);
    $("share-form").reset();
    $("share-output").textContent = "";
    const dialog = $("share-dialog");
    if (dialog.open) dialog.close();
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
    confirmThen(
      `Remove ${name}? Agents lose it at once, and its secret is gone.`,
      "Remove",
      { type: "remove", name },
    );
  }

  // Asks first, then sends `message` to the tray.
  function confirmThen(text, label, message) {
    page.confirming = message;
    $("confirm-text").textContent = text;
    $("confirm-ok").textContent = label;
    $("confirm-dialog").showModal();
  }

  function closeConfirm() {
    page.confirming = null;
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
      if (page.confirming) send(page.confirming);
      closeConfirm();
    });
    $("confirm-cancel").addEventListener("click", closeConfirm);
    $("reveal-close").addEventListener("click", closeReveal);
    $("share-request").addEventListener("click", () => openShare("request"));
    $("share-send").addEventListener("click", () => openShare("send"));
    $("share-receive").addEventListener("click", () => openShare("receive"));
    $("share-form").addEventListener("submit", submitShare);
    $("share-cancel").addEventListener("click", closeShare);
    $("share-copy").addEventListener("click", () => copyText($("share-output"), $("share-copy")));
    $("share-dialog").addEventListener("cancel", (event) => {
      event.preventDefault();
      closeShare();
    });
    $("reveal-dialog").addEventListener("cancel", (event) => {
      event.preventDefault();
      closeReveal();
    });
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
