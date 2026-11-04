// kv's window. The tray sends messages through kv.receive; the page sends
// its own with window.ipc.postMessage. All text from the tray, much of it
// written by agents, goes into the page as text nodes, never as markup.
"use strict";

(() => {
  const $ = (id) => document.getElementById(id);

  const page = {
    // A click on the tray icon shows the small menu first; Open kv grows
    // the window into the full page.
    menu: location.hash === "#menu",
    // The view on show ("menu", "unlock" or "app"), to play its entrance
    // only when it changes; and whether the menu is on its way out.
    view: null,
    expanding: false,
    // Whether a state has come yet: the first one, on load, is not a lock
    // or an unlock.
    seenState: false,
    padlockTimer: null,
    locked: true,
    device: null,
    waiting: false,
    overview: null,
    // Whether kv tray starts at login, and the chosen appearance.
    login: false,
    theme: "system",
    // The screen on show: one of the tray's tabs, or "settings".
    screen: "home",
    // The newest audit entries, for Home and the Audit screen.
    audit: [],
    // What each list was last drawn from, to redraw only on a change.
    drawn: { cards: "", requests: "", handles: "", shares: "", home: "", audit: "" },
    // The longest wait each request has shown, to draw how much is left.
    lifetimes: new Map(),
    handleFilter: "all",
    auditFilter: "all",
    form: null,
    // What the confirm dialog's button sends.
    confirming: null,
    revealTimer: null,
    toastTimer: null,
    // The share dialog's step, while it is open, and whether the tray is
    // working on it.
    share: null,
    shareBusy: false,
    // Whether a file being imported is on show.
    importing: false,
    // Whether a file being kept as a handle is on show.
    file: false,
    // A .kvshare file chosen in the share dialog: its name and text.
    shareFile: null,
    // The received file handle the reveal dialog can save.
    revealFile: null,
  };

  const REVEAL_SECS = 60;
  // The largest file kv imports, as kv-core's import::MAX_FILE_LEN.
  const IMPORT_MAX_BYTES = 64 * 1024;
  // The largest file a handle keeps, as kv-core's secret::MAX_FILE_LEN.
  const FILE_MAX_BYTES = 1024 * 1024;
  // The largest .kvshare file read: a share of the largest file is about 2.5 MB.
  const SHARE_FILE_MAX_BYTES = 3 * 1024 * 1024;
  // Past this many characters a share does not fit one Telegram message.
  const CHAT_MESSAGE_CHARS = 4000;
  // How long the menu takes to fade out before the window grows; as in
  // app.css.
  const LEAVE_MS = 110;
  // How long the lock and unlock animations show before they fade into the
  // view; as in app.css.
  const PADLOCK_MS = 1150;
  const PADLOCK_FADE_MS = 220;
  const TOAST_SECS = 8;

  // The screens, in tab order with Settings last (Ctrl+1 to Ctrl+6), and
  // their titles.
  const SCREENS = ["home", "approvals", "handles", "shares", "audit", "settings"];
  const TITLES = {
    home: "Home",
    approvals: "Approvals",
    handles: "Handles",
    shares: "Shares",
    audit: "Audit log",
    settings: "Settings",
  };
  // The screens the tray knows as tabs; Settings is the page's own.
  const TABS = new Set(["home", "approvals", "handles", "shares", "audit"]);

  const THEMES = [
    ["system", "System", "monitor"],
    ["light", "Light", "sun"],
    ["dark", "Dark", "moon"],
  ];

  // The keys that copy a selection here.
  const COPY_KEYS = /Mac/.test(navigator.platform) ? "⌘C" : "Ctrl+C";

  // What each tool does, in words, and its icon.
  const TOOLS = {
    http_request: ["HTTP request", "globe"],
    exec: ["Run a command", "terminal"],
    run: ["Run a program", "terminal"],
    db_query: ["Database query", "database"],
    db_connect: ["Database lease", "database"],
  };

  // Each kind of handle's icon and tone.
  const KINDS = {
    http: ["globe", "tone-accent"],
    env: ["terminal", "tone-teal"],
    postgres: ["database", "tone-amber"],
    redis: ["layers", "tone-red"],
  };

  // How each mode reads, with its tone and icon.
  const MODES = {
    auto: ["Auto", "tone-green", "check", "Used without asking"],
    ask: ["Ask", "tone-amber", "shield-check", "Each use waits for you"],
    deny: ["Deny", "tone-red", "shield-x", "Never used"],
  };

  // The share dialog's three steps. The tray checks what is typed; the page
  // only shows the fields each step needs.
  const SHARE_STEPS = {
    request: {
      title: "Request a secret",
      icon: ["inbox", "tone-accent"],
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
      icon: ["send", "tone-teal"],
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
      icon: ["download", "tone-amber"],
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
      if (child === null || child === undefined || child === false) continue;
      node.append(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  function icon(name) {
    const node = el("span", `i i-${name}`);
    node.setAttribute("aria-hidden", "true");
    return node;
  }

  // A button with an optional icon; its text is in `.text`, so a copy
  // button can say "Copied" without losing the icon.
  function button(label, onClick, className, iconName) {
    const node = el("button", className || null, iconName ? icon(iconName) : null, el("span", "text", label));
    node.type = "button";
    node.addEventListener("click", onClick);
    return node;
  }

  // A button that is only an icon, named for screen readers.
  function iconButton(name, label, onClick, className) {
    const node = el("button", `icon-button${className ? ` ${className}` : ""}`, icon(name));
    node.type = "button";
    node.setAttribute("aria-label", label);
    node.title = label;
    node.addEventListener("click", onClick);
    return node;
  }

  function chip(text, tone, iconName) {
    return el("span", `chip ${tone}`, iconName ? icon(iconName) : null, text);
  }

  function show(node, shown) {
    node.hidden = !shown;
  }

  // The padlock opens (unlock) or closes (lock) over whatever view is on
  // show, then that view comes in. Skipped when the system asks for less
  // motion.
  function playPadlock(message) {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const node = $("padlock");
    const locking = message.locked;
    let note;
    if (locking) {
      note = "Agents wait until you unlock";
    } else {
      const secs = message.overview && message.overview.status.locks_in_secs;
      note = typeof secs === "number" ? `Locks in ${duration(secs)}` : "Welcome back";
    }
    $("padlock-title").textContent = locking ? "Locked" : "Unlocked";
    $("padlock-note").textContent = note;
    clearTimeout(page.padlockTimer);
    node.classList.remove("play", "done", "locking");
    node.classList.toggle("locking", locking);
    show(node, true);
    void node.offsetWidth;
    node.classList.add("play");
    page.padlockTimer = setTimeout(() => {
      node.classList.add("done");
      if (page.view) enter($(page.view));
      page.padlockTimer = setTimeout(() => {
        show(node, false);
        node.classList.remove("play", "done", "locking");
      }, PADLOCK_FADE_MS);
    }, PADLOCK_MS);
  }

  // Plays a view's entrance again, as when the window shows once more.
  function enter(node) {
    node.classList.remove("enter");
    void node.offsetWidth;
    node.classList.add("enter");
  }

  // "7h 52m", "3m", "40s".
  function duration(secs) {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m`;
    return `${secs}s`;
  }

  // "just now", "4 min ago", "2 h ago", "3 days ago".
  function ago(secs) {
    const past = Math.max(0, Math.floor(Date.now() / 1000) - secs);
    if (past < 45) return "just now";
    if (past < 3600) return `${Math.round(past / 60)} min ago`;
    if (past < 86400) return `${Math.round(past / 3600)} h ago`;
    const days = Math.round(past / 86400);
    return days === 1 ? "yesterday" : `${days} days ago`;
  }

  // A Unix time as the user's local date and time.
  function when(secs) {
    return new Date(secs * 1000).toLocaleString();
  }

  // An agent's initials, and a tone picked from its name so each agent
  // keeps its colour.
  function avatar(name, small) {
    const words = (name || "agent").split(/[^A-Za-z0-9]+/).filter(Boolean);
    const letters = words.length > 1 ? words[0][0] + words[1][0] : (words[0] || "?").slice(0, 2);
    const tones = ["tone-accent", "tone-teal", "tone-amber", "tone-green"];
    let hash = 0;
    for (const c of name || "") hash = (hash * 31 + c.charCodeAt(0)) >>> 0;
    const node = el("span", `avatar ${small ? "sm " : ""}${tones[hash % tones.length]}`, letters.toUpperCase());
    node.setAttribute("aria-hidden", "true");
    return node;
  }

  function tool(name) {
    return TOOLS[name] || [name.replace(/_/g, " "), "sparkles"];
  }

  // Messages from the tray.

  function receive(message) {
    switch (message.type) {
      case "state":
        // Locked a moment ago, unlocked now, or the other way: the padlock
        // opens or closes.
        if (page.seenState && page.locked !== message.locked) playPadlock(message);
        page.seenState = true;
        page.locked = message.locked;
        page.device = message.device;
        page.waiting = message.waiting_for_device;
        page.overview = message.overview;
        if (typeof message.login === "boolean") page.login = message.login;
        if (message.theme) setTheme(message.theme);
        if (page.locked) {
          closeForm(false);
          closeConfirm();
          closeReveal();
          closeShare();
          closeImport(false);
          closeFile(false);
          // Whatever it said belonged to the session that just ended.
          hideToast();
          page.audit = [];
        }
        draw();
        break;
      case "show":
        page.screen = message.tab;
        draw();
        break;
      case "menu":
        // Sent each time the window shows: the view comes in again.
        page.menu = Boolean(message.on);
        draw();
        enter($(page.view));
        break;
      case "hidden":
        // The window went out of sight: values on show go first.
        closeReveal();
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
        page.audit = message.entries;
        drawAudit();
        drawHome();
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
      case "import_preview":
        openImport(message);
        break;
      case "imported":
        closeImport(false);
        say([`Saved ${message.name}.`, ...message.warnings].join(" "));
        break;
      case "file_preview":
        openFile(message);
        break;
      case "file_added":
        closeFile(false);
        say([`Saved ${message.name}.`, ...message.warnings].join(" "));
        break;
      case "file_error":
        $("file-save").disabled = false;
        if (page.file) $("file-error").textContent = message.message;
        else say(message.message);
        break;
      case "share_saved":
        shareSaved(message);
        break;
      case "file_saved":
        fileSaved(message);
        break;
      case "import_error":
        $("import-save").disabled = false;
        if (page.importing) $("import-error").textContent = message.message;
        else say(message.message);
        break;
      case "message":
        say(message.text, message.request);
        break;
    }
  }

  function say(text, request) {
    if (request !== null && request !== undefined) {
      const card = document.querySelector(`.card[data-id="${Number(request)}"]`);
      if (card) {
        card.querySelector(".message").textContent = text;
        for (const b of card.querySelectorAll("button")) b.disabled = false;
        return;
      }
    }
    if (page.locked) {
      $("unlock-message").textContent = text;
    } else {
      $("app-message-text").textContent = text;
      show($("app-message"), true);
      clearTimeout(page.toastTimer);
      page.toastTimer = setTimeout(hideToast, TOAST_SECS * 1000);
    }
  }

  function hideToast() {
    clearTimeout(page.toastTimer);
    $("app-message-text").textContent = "";
    show($("app-message"), false);
  }

  // Appearance: the root's data-theme picks the colours; "system" follows
  // the system's light or dark mode as it changes.
  function setTheme(theme) {
    if (!THEMES.some(([name]) => name === theme)) return;
    page.theme = theme;
    document.documentElement.dataset.theme = theme;
    for (const group of document.querySelectorAll(".theme-choice")) {
      for (const choice of group.children) {
        choice.setAttribute("aria-checked", String(choice.dataset.theme === theme));
      }
    }
  }

  function buildThemeChoices() {
    for (const group of document.querySelectorAll(".theme-choice")) {
      group.replaceChildren(
        ...THEMES.map(([name, label, iconName]) => {
          const choice = button(label, () => {
            // The colours cross-fade into the new theme.
            const root = document.documentElement;
            root.classList.add("theming");
            void root.offsetWidth;
            setTheme(name);
            setTimeout(() => root.classList.remove("theming"), 320);
            send({ type: "theme", theme: name });
          }, null, iconName);
          choice.setAttribute("role", "radio");
          choice.dataset.theme = name;
          return choice;
        }),
      );
    }
    setTheme(page.theme);
  }

  // Drawing.

  function draw() {
    const view = page.menu ? "menu" : page.locked ? "unlock" : "app";
    if (view !== page.view) {
      page.view = view;
      enter($(view));
    }
    show($("menu"), page.menu);
    show($("unlock"), !page.menu && page.locked);
    show($("app"), !page.menu && !page.locked);
    if (page.menu) {
      drawMenu();
    } else if (page.locked) {
      drawUnlock();
    } else {
      drawApp();
    }
  }

  // The small menu: what the tray's own menu offers, in the page's style.
  function drawMenu() {
    const overview = page.locked ? null : page.overview;
    const prompting = Boolean(page.waiting && page.device);
    const secs = overview && overview.status.locks_in_secs;
    let status = "Unlocked";
    if (prompting) status = `Waiting for ${page.device}…`;
    else if (page.locked) status = "Locked";
    else if (typeof secs === "number") status = `Unlocked · locks in ${duration(secs)}`;
    $("menu-status-text").textContent = status;
    $("menu-status").classList.toggle("off", page.locked);

    const approvals = overview ? overview.approvals.length : 0;
    const asked = overview ? overview.handle_requests.length : 0;
    let banner;
    if (page.locked) {
      banner = { tone: "tone-grey", icon: "lock", title: "kv is locked", note: "Unlock to see what agents ask for.", to: null };
    } else if (approvals > 0) {
      const what = approvals === 1 ? "1 request waiting" : `${approvals} requests waiting`;
      banner = { tone: "tone-amber", icon: "bell", title: what, note: "Review them in kv", to: "approvals" };
    } else if (asked > 0) {
      const what = asked === 1 ? "1 handle asked for" : `${asked} handles asked for`;
      banner = { tone: "tone-amber", icon: "bell", title: what, note: "Fill them in in kv", to: "handles" };
    } else {
      banner = { tone: "tone-green", icon: "circle-check", title: "Nothing waiting", note: "No agent needs you right now.", to: null };
    }
    const row = $("menu-waiting");
    row.dataset.to = banner.to || "";
    row.classList.toggle("static", !banner.to);
    row.tabIndex = banner.to ? 0 : -1;
    $("menu-waiting-icon").className = `stat-icon ${banner.tone}`;
    $("menu-waiting-icon").replaceChildren(icon(banner.icon));
    $("menu-waiting-title").textContent = banner.title;
    $("menu-waiting-note").textContent = banner.note;
    show($("menu-waiting-go"), Boolean(banner.to));

    const lock = $("menu-lock");
    let lockIcon = "lock";
    let lockText = "Lock kv";
    if (page.locked && page.device) {
      lockIcon = "fingerprint";
      lockText = `Unlock with ${page.device}`;
    } else if (page.locked) {
      lockIcon = "lock-open";
      lockText = "Unlock kv…";
    }
    $("menu-lock-icon").className = `i i-${lockIcon}`;
    $("menu-lock-text").textContent = lockText;
    lock.disabled = prompting;
    $("menu-login").setAttribute("aria-checked", String(page.login));
  }

  // From the menu to the full window, on `screen` once unlocked.
  // The menu fades out first, so the window grows behind nothing; the full
  // view then comes in.
  function expand(screen) {
    if (page.expanding) return;
    page.expanding = true;
    $("menu").classList.add("leaving");
    setTimeout(() => {
      page.expanding = false;
      $("menu").classList.remove("leaving");
      page.menu = false;
      send({ type: "expand" });
      if (screen && !page.locked) go(screen);
      else draw();
    }, LEAVE_MS);
  }

  function menuLock() {
    if (!page.locked) send({ type: "lock" });
    else if (page.device) send({ type: "device_unlock" });
    else expand(null);
  }

  function drawUnlock() {
    const waiting = Boolean(page.waiting && page.device);
    const waitingNote = $("unlock-waiting");
    waitingNote.textContent = waiting ? `Waiting for ${page.device}…` : "";
    show(waitingNote, waiting);
    const form = $("unlock-form");
    const wasHidden = form.hidden;
    show(form, !waiting);
    const useDevice = $("use-device");
    useDevice.replaceChildren(icon("fingerprint"), el("span", null, page.device ? `Unlock with ${page.device}` : ""));
    const offersDevice = Boolean(page.device) && !waiting;
    show(useDevice, offersDevice);
    show($("unlock-or"), offersDevice);
    if (wasHidden && !waiting && !page.device) $("passphrase").focus();
    page.drawn = { cards: "", requests: "", handles: "", shares: "", home: "", audit: "" };
  }

  function drawApp() {
    $("unlock-message").textContent = "";
    const overview = page.overview;
    const secs = overview && overview.status.locks_in_secs;
    const locksIn = secs === null || secs === undefined ? "Stays unlocked until you lock it" : `Locks in ${duration(secs)}`;
    $("locks-in").textContent = locksIn;
    $("settings-locks-in").textContent = `Unlocked. ${locksIn}.`;
    const soon = typeof secs === "number" && secs < 600;
    $("brand-text").textContent = soon ? `Locks in ${duration(secs)}` : "Unlocked";
    $("brand-status").classList.toggle("soon", soon);

    const approvals = overview ? overview.approvals : [];
    const requests = overview ? overview.handle_requests : [];
    counter("count-approvals", approvals.length, "waiting");
    counter("count-handles", requests.length, "asked for");

    for (const tab of document.querySelectorAll("nav button[data-tab]")) {
      if (tab.dataset.tab === page.screen) tab.setAttribute("aria-current", "page");
      else tab.removeAttribute("aria-current");
    }
    for (const name of SCREENS) show($(name), name === page.screen);
    $("page-title").textContent = page.screen === "home" ? greeting() : TITLES[page.screen] || "kv";
    $("today").textContent = new Date().toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric" });
    $("login").setAttribute("aria-checked", String(page.login));
    if (!overview) return;
    drawHome();
    drawCards(approvals);
    drawRequests(requests);
    drawHandles(overview.handles, overview.role_warnings || {});
    drawShares(overview.shares || { requests: [], received: [], sent: [] }, overview.handles);
  }

  function greeting() {
    const hour = new Date().getHours();
    return hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
  }

  function counter(id, n, what) {
    const node = $(id);
    node.textContent = String(n);
    node.setAttribute("aria-label", `${n} ${what}`);
    show(node, n > 0);
  }

  // Home: what needs the user, the numbers, and the latest activity.
  function drawHome() {
    const overview = page.overview;
    if (!overview || page.locked) return;
    const approvals = overview.approvals;
    const requests = overview.handle_requests;
    const waiting = approvals.length + requests.length;
    $("stat-waiting").textContent = String(waiting);
    $("stat-waiting").closest(".stat").classList.toggle("hot", waiting > 0);
    $("stat-waiting-note").textContent =
      waiting === 0 ? "Nothing waiting" : `${approvals.length} to approve · ${requests.length} asked for`;
    const handles = overview.handles;
    const modes = { auto: 0, ask: 0, deny: 0 };
    for (const h of handles) modes[h.mode] = (modes[h.mode] || 0) + 1;
    $("stat-handles").textContent = String(handles.length);
    $("stat-handles-note").textContent = `${modes.ask} ask · ${modes.auto} auto · ${modes.deny} deny`;
    const shares = overview.shares || { requests: [], received: [], sent: [] };
    const open = shares.requests.filter((r) => !r.expired).length;
    $("stat-shares").textContent = String(open);
    $("stat-shares-note").textContent = `${shares.received.length} received · ${shares.sent.length} sent`;

    const shape = JSON.stringify([approvals.map((a) => a.id), requests.map((r) => r.id), page.audit.slice(0, 5)]);
    if (shape === page.drawn.home) return;
    page.drawn.home = shape;

    // Home only says who is waiting: the answer is given on Approvals, which
    // shows the request in full (the URL, command, query or share).
    // Three rows at most, requests to approve first; the rest is a count.
    const NEEDS_ROWS = 3;
    const shownApprovals = approvals.slice(0, NEEDS_ROWS);
    const shownRequests = requests.slice(0, NEEDS_ROWS - shownApprovals.length);
    const rows = shownApprovals.map((approval) => {
      const handlesText = approval.handles.join(", ");
      return el(
        "div",
        "needs",
        avatar(approval.client, true),
        el("div", "grow", el("strong", null, approval.client || "An agent"), el("span", "muted small", `${tool(approval.tool)[0]} · ${handlesText}`)),
        el("div", "buttons", button("Review", () => go("approvals"), "outline")),
      );
    });
    for (const requested of shownRequests) {
      rows.push(
        el(
          "div",
          "needs",
          avatar(requested.client, true),
          el("div", "grow", el("strong", null, `${requested.client || "An agent"} asked for ${requested.request.name}`), el("span", "muted small", requested.request.reason || requested.request.kind)),
          el("div", "buttons", button("Fill in", () => openRequest({ kind: "request", id: requested.id }), "outline")),
        ),
      );
    }
    const more = approvals.length + requests.length - rows.length;
    if (more > 0) rows.push(el("p", "muted small more", `and ${more} more`));
    $("home-needs").replaceChildren(...rows);
    show($("home-clear"), rows.length === 0);

    const recent = page.audit.slice(0, 5).map(activity);
    $("home-activity").replaceChildren(...recent);
    show($("home-no-activity"), recent.length === 0);
  }

  // How an audit entry went: its tone, icon and word.
  function verdictOf(entry) {
    switch (entry.decision) {
      case "approved":
        return ["tone-green", "check", "Approved"];
      case "auto":
        return ["tone-green", "check", "Auto"];
      case "lease":
        return ["tone-teal", "clock", "Lease"];
      case "denied":
        return ["tone-red", "x", "Denied"];
      case "timed_out":
        return ["tone-amber", "hourglass", "Timed out"];
      default:
        return ["tone-grey", "info", null];
    }
  }

  function actionWords(action) {
    const words = {
      http_request: "HTTP request",
      db_query: "Database query",
      db_connect: "Database lease",
      exec: "Command",
      run: "Program",
      unlock: "Unlocked",
      open_session: "Unlocked",
      lock: "Locked",
      idle_lock: "Locked when idle",
      stop: "Stopped kv",
      init: "Created the vault",
      add: "Added handle",
      remove: "Removed handle",
      set_policy: "Changed policy",
      update: "Updated handle",
      change_passphrase: "Changed passphrase",
      overview: "Opened kv",
      status: "Checked status",
      decide: "Answered a request",
      dismiss_request: "Dismissed a request",
      enroll_device: "Added a device",
      remove_device: "Removed a device",
      reveal_share: "Revealed a share",
      forget_share: "Forgot a share",
      request_share: "Asked for a share",
      send_share: "Sent a share",
      receive_share: "Received a share",
      list_handles: "Listed handles",
      request_handle: "Asked for a handle",
    };
    return words[action] || action.replace(/_/g, " ");
  }

  function entryTime(entry) {
    return Date.parse(entry.ts) / 1000;
  }

  function activity(entry) {
    const [tone, iconName] = verdictOf(entry);
    const mark = el("span", `mark ${tone}`, icon(iconName));
    // The handle leads the second line, so a narrow column cuts the
    // summary rather than the handle's name.
    const detail = [entry.handle, entry.summary].filter(Boolean).join(" · ");
    const time = el("span", "muted small", ago(entryTime(entry)));
    return el("li", null, mark, el("div", "what", el("strong", null, actionWords(entry.action)), detail ? el("span", "muted small code", detail) : null), time);
  }

  function drawCards(approvals) {
    show($("no-approvals"), approvals.length === 0);
    for (const approval of approvals) {
      const seen = page.lifetimes.get(approval.id) || 0;
      page.lifetimes.set(approval.id, Math.max(seen, approval.expires_in_secs));
    }
    // The countdowns change every second; the cards only when requests come
    // or go, so a button the user is about to press stays put.
    const shape = JSON.stringify(approvals.map((a) => ({ ...a, expires_in_secs: 0 })));
    if (shape !== page.drawn.cards) {
      page.drawn.cards = shape;
      const kept = new Map();
      for (const card of $("cards").children) kept.set(card.dataset.id, card);
      const cards = approvals.map((approval) => kept.get(String(approval.id)) || card(approval));
      $("cards").replaceChildren(...cards);
      const ids = new Set(approvals.map((a) => a.id));
      for (const id of page.lifetimes.keys()) if (!ids.has(id)) page.lifetimes.delete(id);
    }
    for (const approval of approvals) {
      const timer = document.querySelector(`.card[data-id="${Number(approval.id)}"] .timer`);
      if (!timer) continue;
      const left = approval.expires_in_secs;
      timer.querySelector(".expires").textContent = `Expires in ${left}s`;
      const bar = timer.querySelector("progress");
      bar.max = page.lifetimes.get(approval.id) || left || 1;
      bar.value = left;
      timer.classList.toggle("soon", left <= 15);
    }
  }

  function card(approval) {
    const handles = approval.handles.join(", ");
    const [toolName, toolIcon] = tool(approval.tool);
    const node = el("article", "card waiting-card");
    const decide = (verdict) => () => {
      for (const b of node.querySelectorAll(".buttons button")) b.disabled = true;
      send({ type: "decide", id: approval.id, verdict });
    };
    const bar = el("progress");
    bar.setAttribute("aria-label", "Time left to answer");
    const parts = [
      el(
        "div",
        "card-head",
        avatar(approval.client),
        el("div", "grow", el("div", "title", approval.client || "An agent"), el("div", "sub", `wants to use ${handles}`)),
        chip(toolName, "tone-accent", toolIcon),
      ),
      el("div", "chips", ...approval.handles.map((h) => chip(h, "tone-grey", "key-round"))),
      el("div", "code-box", approval.detail),
      approval.cwd ? el("div", "meta", icon("folder"), `in ${approval.cwd}`) : null,
      approval.env_vars && approval.env_vars.length ? el("div", "meta", icon("key-round"), `with ${approval.env_vars.join(", ")}`) : null,
      el("div", "timer", bar, el("span", "expires", `Expires in ${approval.expires_in_secs}s`)),
      el(
        "div",
        "buttons",
        button("Allow once", decide("allow_once"), "primary", "check"),
        approval.can_grant ? button("Allow for this session", decide("allow_session"), "outline") : null,
        button("Deny", decide("deny"), "outline danger"),
        button(`Deny and block ${handles}`, decide("deny_always"), "danger", "shield-x"),
      ),
      el("p", "message"),
    ];
    node.append(...parts.filter(Boolean));
    node.dataset.id = String(approval.id);
    node.setAttribute("aria-label", `${approval.client || "An agent"}: ${toolName} with ${handles}`);
    return node;
  }

  function drawRequests(requests) {
    const shape = JSON.stringify(requests);
    if (shape === page.drawn.requests) return;
    page.drawn.requests = shape;
    const cards = requests.map((requested) => {
      const r = requested.request;
      const allows = r.kind === "env" ? r.env_vars : r.allowed_hosts;
      const [kindIcon, tone] = KINDS[r.kind] || ["key-round", "tone-accent"];
      return el(
        "article",
        "card request-card",
        el(
          "div",
          "card-head",
          avatar(requested.client),
          el("div", "grow", el("div", "title", `${requested.client || "An agent"} asked for a handle`), el("div", "sub", r.description || r.name)),
          chip(r.kind, tone, kindIcon),
        ),
        el("div", "chips", chip(r.name, "tone-grey", "key-round"), ...allows.map((a) => chip(a, "tone-grey"))),
        r.reason ? el("div", "meta", icon("info"), `Why: ${r.reason}`) : null,
        el(
          "div",
          "buttons",
          button("Fill in", () => openRequest({ kind: "request", id: requested.id }), "primary", "pencil"),
          button("Dismiss", () => send({ type: "dismiss", id: requested.id }), "outline"),
        ),
      );
    });
    $("requests").replaceChildren(...cards);
  }

  function drawHandles(handles, warnings) {
    const query = $("handle-search").value.trim().toLowerCase();
    const shape = JSON.stringify([handles, warnings, query, page.handleFilter]);
    if (shape === page.drawn.handles) return;
    page.drawn.handles = shape;
    show($("no-handles"), handles.length === 0);
    const shown = handles.filter(
      (h) =>
        (page.handleFilter === "all" || h.mode === page.handleFilter) &&
        (!query || `${h.name} ${h.description} ${h.kind}`.toLowerCase().includes(query)),
    );
    show($("no-match"), handles.length > 0 && shown.length === 0);
    show($("handle-rows"), shown.length > 0);
    const rows = shown.map((handle) => {
      const allows = {
        http: [...handle.allowed_hosts, ...handle.allowed_methods],
        env: handle.allowed_cmds,
      }[handle.kind];
      const [kindIcon, tone] = KINDS[handle.kind] || ["key-round", "tone-accent"];
      const [modeText, modeTone, modeIcon, modeHint] = MODES[handle.mode] || [handle.mode, "tone-grey", "info", ""];
      const mode = chip(modeText, modeTone, modeIcon);
      mode.title = modeHint;
      const info = el(
        "div",
        "grow",
        el("div", "chips", el("span", "name", handle.name), chip(handle.kind, "tone-grey"), mode, handle.read_only ? chip("read only", "tone-teal", "eye") : null),
        handle.description ? el("span", "desc", handle.description) : null,
        allows && allows.length > 0 ? el("span", "allows", allows.join(" · ")) : null,
        warnings[handle.name] ? el("div", "warning", icon("triangle-alert"), warnings[handle.name]) : null,
      );
      const remove = iconButton("trash-2", `Remove ${handle.name}`, () => confirmRemove(handle.name), "danger");
      remove.dataset.action = "remove";
      return el(
        "li",
        "row-item",
        el("span", `stat-icon ${tone}`, icon(kindIcon)),
        info,
        el(
          "div",
          "row-actions",
          iconButton("pencil", `Edit ${handle.name}`, () => openRequest({ kind: "edit", name: handle.name })),
          iconButton("sliders-horizontal", `Policy for ${handle.name}`, () => openRequest({ kind: "policy", name: handle.name })),
          remove,
        ),
      );
    });
    $("handle-rows").replaceChildren(...rows);
  }

  function drawShares(shares, handles) {
    const shape = JSON.stringify([shares, handles.map((h) => h.name)]);
    if (shape === page.drawn.shares) return;
    page.drawn.shares = shape;

    show($("no-share-requests"), shares.requests.length === 0);
    const requests = shares.requests.map((request) => {
      const status = request.expired
        ? `Expired ${when(request.expires_at)}`
        : `Opened ${ago(request.created_at)} · open until ${when(request.expires_at)}`;
      const code = el("div", "code-box share-output", request.code);
      return el(
        "article",
        "card",
        el(
          "div",
          "card-head",
          el("span", "stat-icon tone-accent", icon("inbox")),
          el("div", "grow", el("div", "title", request.note || "A secret you asked for"), el("div", "sub muted small", status)),
          chip(request.safety_code, request.expired ? "tone-grey" : "tone-amber", "shield-check"),
        ),
        request.expired ? null : code,
        el(
          "div",
          "buttons",
          request.expired ? null : button("Copy code", (event) => copyText(code, event.currentTarget.querySelector(".text")), "primary", "copy"),
          button(
            request.expired ? "Remove" : "Cancel request",
            () =>
              confirmThen(
                `Cancel request ${request.safety_code}? A share sealed to it can no longer be opened.`,
                "Cancel request",
                { type: "forget", id: request.id },
              ),
            "outline danger",
          ),
        ),
      );
    });
    $("share-requests").replaceChildren(...requests);

    const names = new Set(handles.map((h) => h.name));
    const forget = (id, what) =>
      iconButton("trash-2", `Forget ${what}`, () => confirmThen(`Forget ${what}? This only clears the record.`, "Forget", { type: "forget", id }), "danger");

    show($("no-received"), shares.received.length === 0);
    $("received-rows").replaceChildren(
      ...shares.received
        .slice()
        .reverse()
        .map((r) => {
          let state = null;
          if (!names.has(r.handle)) state = el("span", "desc", "Removed since");
          else if (!r.viewable) state = el("span", "desc", "Changed since, so kv no longer shows it");
          return el(
            "li",
            "row-item",
            el("span", "stat-icon tone-amber", icon("download")),
            el(
              "div",
              "grow",
              el("div", "chips", el("span", "name", r.handle), chip(r.kind, "tone-grey")),
              el("span", "desc", `from ${r.from || "not given"} · ${ago(r.received_at)}${r.note ? ` · ${r.note}` : ""}`),
              el("span", "allows", `Safety code ${r.safety_code}`),
              state,
            ),
            el(
              "div",
              "row-actions",
              r.viewable
                ? r.kind === "file"
                  ? iconButton("download", `Save ${r.handle} as a file`, () => send({ type: "reveal", handle: r.handle }))
                  : iconButton("eye", `View ${r.handle}`, () => send({ type: "reveal", handle: r.handle }))
                : null,
              forget(r.id, `the record of ${r.handle}`),
            ),
          );
        }),
    );

    show($("no-sent"), shares.sent.length === 0);
    $("sent-rows").replaceChildren(
      ...shares.sent
        .slice()
        .reverse()
        .map((s) =>
          el(
            "li",
            "row-item",
            el("span", "stat-icon tone-teal", icon("send")),
            el(
              "div",
              "grow",
              el("div", "chips", el("span", "name", s.handle), chip(s.kind, "tone-grey")),
              el("span", "desc", `to ${s.to || "not given"} · ${ago(s.sent_at)}${s.note ? ` · ${s.note}` : ""}`),
              el("span", "allows", `Safety code ${s.safety_code}`),
            ),
            el("div", "row-actions", forget(s.id, `the record of sending ${s.handle}`)),
          ),
        ),
    );
  }

  // A received value, drawn as text the user can select, and wiped when the
  // dialog closes, the timer runs out, the window hides or the vault locks.
  function openReveal(handle, fields) {
    $("reveal-title").textContent = handle;
    $("reveal-fields").replaceChildren(
      ...fields.map((f) => el("div", "field", el("label", null, f.label), el("div", "code-box secret-value", f.value))),
    );
    // A received file can be saved as it is; nothing else has a Save.
    const info = ((page.overview && page.overview.handles) || []).find((h) => h.name === handle);
    page.revealFile = info && info.kind === "file" ? handle : null;
    $("reveal-save").disabled = false;
    show($("reveal-save"), page.revealFile !== null);
    show($("reveal-show"), false);
    show($("reveal-status"), false);
    $("reveal-status").textContent = "";
    const dialog = $("reveal-dialog");
    if (!dialog.open) dialog.showModal();
    clearTimeout(page.revealTimer);
    page.revealTimer = setTimeout(closeReveal, REVEAL_SECS * 1000);
  }

  // A received file was written to the Downloads folder.
  function fileSaved(saved) {
    $("reveal-save").disabled = false;
    if (!$("reveal-dialog").open) {
      say(`Saved ${saved.handle} to ${saved.path}.`);
      return;
    }
    $("reveal-status").textContent = `Saved to ${saved.path}`;
    show($("reveal-status"), true);
    show($("reveal-show"), true);
  }

  function closeReveal() {
    clearTimeout(page.revealTimer);
    page.revealTimer = null;
    $("reveal-fields").replaceChildren();
    $("reveal-title").textContent = "";
    page.revealFile = null;
    show($("reveal-save"), false);
    show($("reveal-show"), false);
    show($("reveal-status"), false);
    $("reveal-status").textContent = "";
    const dialog = $("reveal-dialog");
    if (dialog.open) dialog.close();
  }

  // Copies `node`'s text. The copy command needs the text selected; where
  // it fails, the clipboard API may still work, and failing that the text
  // stays selected for the user's own keys. `label` says how it went.
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
    $("share-icon").className = `stat-icon ${spec.icon[1]}`;
    $("share-icon").replaceChildren(icon(spec.icon[0]));
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
    clearShareFile();
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
          $("share-error").textContent = "Pick a handle to send; add one on the Handles screen first.";
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
        message = {
          type: "receive_share",
          share: page.shareFile ? page.shareFile.text : value("share-code"),
          name: value("share-name"),
        };
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
        if ([...output].length > CHAT_MESSAGE_CHARS) {
          about += " It is longer than one Telegram message, so send it as a text file rather than splitting it.";
        }
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
          "Handles screen.";
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

  // A share too long for a message was saved as a file: show where, to
  // send as an attachment.
  function shareSaved(result) {
    shareBusy(false);
    if (!page.share) return;
    let about =
      `Saved as a file, because it is too long for a chat message. Send that file to ${result.to || "them"} ` +
      "as an attachment, exactly as it is and not as text. Only the vault that made the request can open it.";
    if (result.asked_for) about += ` They asked for: ${result.asked_for}`;
    $("share-result-about").textContent = about;
    $("share-output").textContent = result.path;
    show($("share-output"), true);
    $("share-safety").textContent =
      `Safety code ${result.safety_code}. Anyone in the chat could have posted that request: ` +
      "for anything sensitive, check over a call that their request shows the same code before " +
      "you send this.";
    shareResult(true);
    show($("share-copy"), true);
    show($("share-show"), true);
    $("share-show").focus();
  }

  // Chooses a .kvshare file to receive, or lets go of the one chosen.
  function pickShareFile() {
    if (page.shareFile) {
      clearShareFile();
      return;
    }
    const input = $("share-file");
    input.value = "";
    input.click();
  }

  function readShareFile() {
    const input = $("share-file");
    const file = input.files && input.files[0];
    if (!file) return;
    if (file.size > SHARE_FILE_MAX_BYTES) {
      input.value = "";
      $("share-error").textContent = `${file.name} is too large to be a kv share.`;
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      input.value = "";
      page.shareFile = { name: file.name, text: String(reader.result) };
      $("share-code").value = "";
      $("share-code").disabled = true;
      $("share-code").placeholder = `Using ${file.name}`;
      $("share-pick-text").textContent = "Use pasted text instead";
      $("share-error").textContent = "";
    };
    reader.onerror = () => {
      input.value = "";
      $("share-error").textContent = `Could not read ${file.name}.`;
    };
    reader.readAsText(file);
  }

  function clearShareFile() {
    page.shareFile = null;
    $("share-code").disabled = false;
    $("share-pick-text").textContent = "Choose a .kvshare file";
    const spec = SHARE_STEPS[page.share];
    if (spec && spec.code) $("share-code").placeholder = spec.code[1];
  }

  function shareResult(shown) {
    show($("share-ask"), !shown);
    show($("share-about"), !shown);
    show($("share-result"), shown);
    show($("share-submit"), !shown);
    show($("share-copy"), false);
    show($("share-show"), false);
    $("share-cancel").textContent = shown ? "Done" : "Cancel";
  }

  // Closes the share dialog and drops what was typed and shown.
  function closeShare() {
    clearShareFile();
    page.share = null;
    shareBusy(false);
    $("share-form").reset();
    $("share-output").textContent = "";
    const dialog = $("share-dialog");
    if (dialog.open) dialog.close();
  }

  function drawAudit() {
    const query = $("audit-search").value.trim().toLowerCase();
    const shape = JSON.stringify([page.audit, query, page.auditFilter]);
    if (shape === page.drawn.audit) return;
    page.drawn.audit = shape;
    const entries = page.audit;
    show($("no-audit"), entries.length === 0);
    const allowed = new Set(["approved", "auto", "lease"]);
    const shown = entries.filter((e) => {
      if (page.auditFilter === "allowed" && !allowed.has(e.decision)) return false;
      if (page.auditFilter === "denied" && e.decision !== "denied" && e.decision !== "timed_out") return false;
      return !query || [e.action, e.handle, e.decision, e.outcome, e.summary].join(" ").toLowerCase().includes(query);
    });
    show($("no-audit-match"), entries.length > 0 && shown.length === 0);
    show($("audit-rows"), shown.length > 0);
    const rows = shown.map((e) => {
      const [tone, iconName, word] = verdictOf(e);
      const at = entryTime(e);
      const time = el("div", "when", ago(at));
      // The exact time, and the log's own in UTC, as kv tui shows it.
      time.title = `${new Date(at * 1000).toLocaleString()} (${e.ts.slice(0, 19).replace("T", " ")} UTC)`;
      // The outcome only where it says more than the decision does.
      const said = new Set([e.decision, word && word.toLowerCase(), "ok", "done", "denied", "timeout", "approved"]);
      const outcome = e.outcome && !said.has(String(e.outcome).toLowerCase()) ? chip(e.outcome, "tone-grey") : null;
      return el(
        "li",
        "row-item",
        el("span", `mark ${tone}`, icon(iconName)),
        el(
          "div",
          "grow",
          el(
            "div",
            "chips",
            el("span", "name", actionWords(e.action)),
            e.handle ? chip(e.handle, "tone-grey", "key-round") : null,
            word ? chip(word, tone) : null,
            outcome,
          ),
          e.summary ? el("span", "summary", e.summary) : null,
        ),
        time,
      );
    });
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
    }, "outline", "plus");
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
    row.append(iconButton("x", "Remove this variable", () => row.remove(), "danger"));
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
      `Remove ${name}?`,
    );
  }

  // Asks first, then sends `message` to the tray.
  function confirmThen(text, label, message, title) {
    page.confirming = message;
    $("confirm-title").textContent = title || `${label}?`;
    $("confirm-text").textContent = text;
    $("confirm-ok").textContent = label;
    $("confirm-dialog").showModal();
  }

  function closeConfirm() {
    page.confirming = null;
    const dialog = $("confirm-dialog");
    if (dialog.open) dialog.close();
  }

  // Moves to a screen; the tray hears about its own tabs.
  function go(screen) {
    // A new screen starts at its top.
    if (screen !== page.screen) document.querySelector(".scroll").scrollTop = 0;
    page.screen = screen;
    hideToast();
    if (TABS.has(screen)) send({ type: "tab", tab: screen });
    draw();
    $("page-title").focus({ preventScroll: true });
  }

  // Opens the file panel; what is picked goes to the tray, which answers
  // with the variables' names and never their values.
  function pickImport() {
    const input = $("import-file");
    input.value = "";
    input.click();
  }

  function readImport() {
    const input = $("import-file");
    const file = input.files && input.files[0];
    if (!file) return;
    const done = () => {
      input.value = "";
    };
    if (file.size > IMPORT_MAX_BYTES) {
      done();
      say(`${file.name} is larger than 64 KiB. kv imports .env and JSON settings files.`);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      done();
      send({ type: "import_file", file_name: file.name, text: String(reader.result) });
    };
    reader.onerror = () => {
      done();
      say(`Could not read ${file.name}.`);
    };
    reader.readAsText(file);
  }

  function openImport(preview) {
    page.importing = true;
    const count = preview.vars.length;
    $("import-about").textContent =
      `${preview.file_name}, read as ${preview.format}: ${count} variable${count === 1 ? "" : "s"}. ` +
      "Tick the ones to keep.";
    $("import-name").value = preview.name;
    $("import-error").textContent = "";
    $("import-save").disabled = false;
    const rows = preview.vars.map((v) => {
      const box = el("input");
      box.type = "checkbox";
      box.checked = v.keep;
      box.value = v.name;
      const row = el("label", "import-var", box, el("span", "name", v.name), v.risky ? chip("changes how programs run", "tone-amber", "triangle-alert") : null);
      if (v.risky) row.title = "It can change what a program runs or where it connects, so it starts unticked.";
      return row;
    });
    $("import-vars").replaceChildren(...rows);
    $("import-note-list").replaceChildren(...preview.notes.map((n) => el("li", null, n)));
    show($("import-notes"), preview.notes.length > 0);
    const dialog = $("import-dialog");
    if (!dialog.open) dialog.showModal();
    $("import-name").focus();
  }

  function tickImport(on) {
    for (const box of $("import-vars").querySelectorAll("input")) box.checked = on;
  }

  function submitImport(event) {
    event.preventDefault();
    if (!page.importing) return;
    const keep = [...$("import-vars").querySelectorAll("input:checked")].map((box) => box.value);
    $("import-error").textContent = "";
    $("import-save").disabled = true;
    send({ type: "import_save", name: $("import-name").value.trim(), keep });
  }

  // Closes the import and drops the names shown. `tell` says the tray
  // still holds the file.
  function closeImport(tell) {
    const dialog = $("import-dialog");
    const was = page.importing;
    page.importing = false;
    $("import-form").reset();
    $("import-vars").replaceChildren();
    $("import-note-list").replaceChildren();
    $("import-error").textContent = "";
    if (dialog.open) dialog.close();
    if (tell && was) send({ type: "import_cancel" });
  }

  // Opens the file panel for a file to keep as a handle. Any file goes, up
  // to 1 MiB; the tray answers with what it is, never what it holds.
  function pickFile() {
    const input = $("add-file-input");
    input.value = "";
    input.click();
  }

  // The bytes as base64, in pieces so a large file does not overflow the
  // call stack.
  function toBase64(bytes) {
    let binary = "";
    const step = 0x8000;
    for (let at = 0; at < bytes.length; at += step) {
      binary += String.fromCharCode.apply(null, bytes.subarray(at, at + step));
    }
    return btoa(binary);
  }

  function readFile() {
    const input = $("add-file-input");
    const file = input.files && input.files[0];
    if (!file) return;
    const done = () => {
      input.value = "";
    };
    if (file.size > FILE_MAX_BYTES) {
      done();
      say(`${file.name} is larger than 1 MiB, which a file handle holds.`);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      done();
      send({ type: "file_read", file_name: file.name, data: toBase64(new Uint8Array(reader.result)) });
    };
    reader.onerror = () => {
      done();
      say(`Could not read ${file.name}.`);
    };
    reader.readAsArrayBuffer(file);
  }

  function fileSize(bytes) {
    if (bytes < 1024) return `${bytes} bytes`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
  }

  function openFile(preview) {
    page.file = true;
    $("file-about").textContent =
      `${preview.file_name}, ${fileSize(preview.size)}, fingerprint ${preview.fingerprint}. ` +
      "kv keeps it exactly as it is and gives a program the file; agents never see what is in it.";
    $("file-name").value = preview.name;
    $("file-cmds").value = "";
    $("file-error").textContent = "";
    $("file-save").disabled = false;
    $("file-note-list").replaceChildren(...preview.notes.map((n) => el("li", null, n)));
    show($("file-notes"), preview.notes.length > 0);
    const dialog = $("file-dialog");
    if (!dialog.open) dialog.showModal();
    $("file-name").focus();
  }

  function submitFile(event) {
    event.preventDefault();
    if (!page.file) return;
    $("file-error").textContent = "";
    $("file-save").disabled = true;
    send({ type: "file_save", name: $("file-name").value.trim(), cmds: $("file-cmds").value });
  }

  // Closes the file dialog. `tell` says the tray still holds the file.
  function closeFile(tell) {
    const dialog = $("file-dialog");
    const was = page.file;
    page.file = false;
    $("file-form").reset();
    $("file-note-list").replaceChildren();
    $("file-error").textContent = "";
    if (dialog.open) dialog.close();
    if (tell && was) send({ type: "file_cancel" });
  }

  function anyDialogOpen() {
    return [...document.querySelectorAll("dialog")].some((d) => d.open);
  }

  function onKey(event) {
    if (page.menu) {
      if (event.key === "Escape") send({ type: "hide" });
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        const items = [...document.querySelectorAll("#menu-waiting:not(.static), .menu-list button:not(:disabled)")];
        const at = items.indexOf(document.activeElement);
        const next = event.key === "ArrowDown" ? at + 1 : at - 1;
        items[(next + items.length) % items.length].focus();
      }
      return;
    }
    if (page.locked) {
      if (event.key === "Escape") send({ type: "hide" });
      return;
    }
    const typing = /^(INPUT|SELECT)$/.test(document.activeElement && document.activeElement.tagName);
    if ((event.ctrlKey || event.metaKey) && /^[1-6]$/.test(event.key)) {
      event.preventDefault();
      if (!anyDialogOpen()) go(SCREENS[Number(event.key) - 1]);
    } else if (event.key === "/" && !typing && !anyDialogOpen()) {
      const search = page.screen === "audit" ? $("audit-search") : $("handle-search");
      if (page.screen !== "audit" && page.screen !== "handles") go("handles");
      event.preventDefault();
      search.focus();
    } else if (event.key === "Escape" && !anyDialogOpen()) {
      // A dialog's own Esc closes it; with none open, Esc hides kv.
      if (typing && event.target.value) {
        event.target.value = "";
        event.target.dispatchEvent(new Event("input"));
      } else {
        send({ type: "hide" });
      }
    }
  }

  // A segmented filter: one choice checked at a time.
  function wireFilter(groupId, onPick) {
    for (const choice of $(groupId).querySelectorAll("button")) {
      choice.addEventListener("click", () => {
        for (const other of $(groupId).querySelectorAll("button")) {
          other.setAttribute("aria-checked", String(other === choice));
        }
        onPick(choice.dataset.filter);
      });
    }
  }

  function askQuit() {
    confirmThen(
      "Quit kv tray? Agents' requests then wait for kv tui or time out. Start it again with kv tray.",
      "Quit",
      { type: "quit" },
      "Quit kv tray?",
    );
  }

  // Wiring.

  function start() {
    buildThemeChoices();
    $("page-title").tabIndex = -1;
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
    $("settings-lock").addEventListener("click", () => send({ type: "lock" }));
    $("hide").addEventListener("click", () => send({ type: "hide" }));
    $("app-message-close").addEventListener("click", hideToast);
    for (const quit of document.querySelectorAll("[data-quit]")) quit.addEventListener("click", askQuit);
    $("login").addEventListener("click", () => {
      page.login = !page.login;
      $("login").setAttribute("aria-checked", String(page.login));
      send({ type: "login", on: page.login });
    });
    $("add").addEventListener("click", () => openRequest({ kind: "new" }));
    $("import").addEventListener("click", pickImport);
    $("import-file").addEventListener("change", readImport);
    $("import-form").addEventListener("submit", submitImport);
    $("import-all").addEventListener("click", () => tickImport(true));
    $("import-none").addEventListener("click", () => tickImport(false));
    $("import-cancel").addEventListener("click", () => closeImport(true));
    $("import-x").addEventListener("click", () => closeImport(true));
    $("import-dialog").addEventListener("cancel", (event) => {
      event.preventDefault();
      closeImport(true);
    });
    $("add-file").addEventListener("click", pickFile);
    $("add-file-input").addEventListener("change", readFile);
    $("file-form").addEventListener("submit", submitFile);
    $("file-cancel").addEventListener("click", () => closeFile(true));
    $("file-x").addEventListener("click", () => closeFile(true));
    $("file-dialog").addEventListener("cancel", (event) => {
      event.preventDefault();
      closeFile(true);
    });
    for (const tab of document.querySelectorAll("nav button[data-tab]")) {
      tab.addEventListener("click", () => go(tab.dataset.tab));
    }
    for (const link of document.querySelectorAll("[data-goto]")) {
      link.addEventListener("click", () => go(link.dataset.goto));
    }
    $("menu-open").addEventListener("click", () => expand(null));
    $("menu-waiting").addEventListener("click", () => {
      const to = $("menu-waiting").dataset.to;
      if (to) expand(to);
    });
    $("menu-lock").addEventListener("click", menuLock);
    $("menu-login").addEventListener("click", () => {
      page.login = !page.login;
      $("menu-login").setAttribute("aria-checked", String(page.login));
      send({ type: "login", on: page.login });
    });
    $("menu-quit").addEventListener("click", () => send({ type: "quit" }));
    $("menu-hide").addEventListener("click", () => send({ type: "hide" }));
    const quick = {
      add: () => openRequest({ kind: "new" }),
      request: () => openShare("request"),
      send: () => openShare("send"),
      receive: () => openShare("receive"),
    };
    for (const action of document.querySelectorAll("[data-go]")) {
      action.addEventListener("click", quick[action.dataset.go]);
    }
    $("handle-search").addEventListener("input", () => page.overview && drawHandles(page.overview.handles, page.overview.role_warnings || {}));
    $("audit-search").addEventListener("input", drawAudit);
    wireFilter("handle-filter", (filter) => {
      page.handleFilter = filter;
      if (page.overview) drawHandles(page.overview.handles, page.overview.role_warnings || {});
    });
    wireFilter("audit-filter", (filter) => {
      page.auditFilter = filter;
      drawAudit();
    });
    $("form").addEventListener("submit", submitForm);
    $("form-cancel").addEventListener("click", () => closeForm(true));
    $("form-x").addEventListener("click", () => closeForm(true));
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
    $("reveal-save").addEventListener("click", () => {
      if (!page.revealFile) return;
      $("reveal-save").disabled = true;
      send({ type: "save_file", handle: page.revealFile });
    });
    $("reveal-show").addEventListener("click", () => send({ type: "show_saved" }));
    $("share-show").addEventListener("click", () => send({ type: "show_saved" }));
    $("share-pick").addEventListener("click", pickShareFile);
    $("share-file").addEventListener("change", readShareFile);
    $("share-request").addEventListener("click", () => openShare("request"));
    $("share-send").addEventListener("click", () => openShare("send"));
    $("share-receive").addEventListener("click", () => openShare("receive"));
    $("share-form").addEventListener("submit", submitShare);
    $("share-cancel").addEventListener("click", closeShare);
    $("share-x").addEventListener("click", closeShare);
    $("share-copy").addEventListener("click", () => copyText($("share-output"), $("share-copy").querySelector(".copy-label")));
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
    document.addEventListener("keydown", onKey);
    draw();
    send({ type: "ready" });
  }

  window.kv = Object.freeze({ receive });
  start();
})();
