// CopyTo — real-time shared clipboard on Cloudflare Workers + Durable Objects.
//
// One shared text pane. Open the page on two machines, type/paste on one,
// it appears on the other within a few hundred ms. Password-gated so only
// people with the shared secret can join a room.
//
// Architecture:
//   - The Worker serves the HTML page and upgrades /ws requests to WebSocket.
//   - A single Durable Object ("Room") holds the current text and fans out
//     updates to every connected client. State is in-memory + the DO's
//     storage, so a late joiner immediately gets the latest text.

const ROOM_NAME = "main"; // single shared room; extendable to multi-room later

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ws") {
      // Auth happens here, before touching the Durable Object.
      const pass = url.searchParams.get("p") || "";
      if (!env.ROOM_PASSWORD) {
        return new Response("Server missing ROOM_PASSWORD secret", { status: 500 });
      }
      if (!timingSafeEqual(pass, env.ROOM_PASSWORD)) {
        return new Response("Unauthorized", { status: 401 });
      }
      const id = env.ROOMS.idFromName(ROOM_NAME);
      const stub = env.ROOMS.get(id);
      return stub.fetch(request);
    }

    if (url.pathname === "/" || url.pathname === "/index.html") {
      return new Response(PAGE, {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    return new Response("Not found", { status: 404 });
  },
};

// Constant-time-ish string comparison so the password check doesn't leak
// length/prefix info through response timing.
function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const ba = enc.encode(a);
  const bb = enc.encode(b);
  if (ba.length !== bb.length) {
    // Still run a compare to avoid an obvious early-exit timing signal.
    let diff = 1;
    for (let i = 0; i < Math.max(ba.length, bb.length); i++) {
      diff |= (ba[i % ba.length || 0] ^ bb[i % bb.length || 0]);
    }
    return false;
  }
  let diff = 0;
  for (let i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
  return diff === 0;
}

export class Room {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Set();
    this.text = "";
    this.rev = 0;
    // Load persisted text on first access.
    this.state.blockConcurrencyWhile(async () => {
      this.text = (await this.state.storage.get("text")) || "";
      this.rev = (await this.state.storage.get("rev")) || 0;
    });
  }

  async fetch(request) {
    const upgrade = request.headers.get("Upgrade");
    if (upgrade !== "websocket") {
      return new Response("Expected WebSocket", { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    this.handleSession(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  handleSession(ws) {
    ws.accept();
    this.sessions.add(ws);

    // Send current state to the new client immediately.
    ws.send(JSON.stringify({ type: "init", text: this.text, rev: this.rev }));

    ws.addEventListener("message", async (evt) => {
      let msg;
      try {
        msg = JSON.parse(evt.data);
      } catch {
        return;
      }
      if (msg.type === "update" && typeof msg.text === "string") {
        // Cap at ~1MB to avoid runaway payloads.
        if (msg.text.length > 1_000_000) return;
        this.text = msg.text;
        this.rev++;
        await this.state.storage.put("text", this.text);
        await this.state.storage.put("rev", this.rev);
        this.broadcast(
          JSON.stringify({ type: "update", text: this.text, rev: this.rev }),
          ws
        );
      }
    });

    const close = () => this.sessions.delete(ws);
    ws.addEventListener("close", close);
    ws.addEventListener("error", close);
  }

  broadcast(data, except) {
    for (const ws of this.sessions) {
      if (ws === except) continue;
      try {
        ws.send(data);
      } catch {
        this.sessions.delete(ws);
      }
    }
  }
}

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>CopyTo</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    background: #0f1115; color: #e6e6e6; height: 100vh;
    display: flex; flex-direction: column;
  }
  header {
    padding: 10px 16px; display: flex; align-items: center; gap: 12px;
    border-bottom: 1px solid #262a33; font-size: 13px;
  }
  header .dot { width: 9px; height: 9px; border-radius: 50%; background: #e0b341; transition: background .2s; }
  header .dot.on { background: #3fb950; }
  header .dot.off { background: #f85149; }
  header .spacer { flex: 1; }
  header button { background: #21262d; color: #e6e6e6; border: 1px solid #30363d; border-radius: 6px; padding: 5px 10px; font: inherit; font-size: 12px; cursor: pointer; }
  header button:hover { background: #30363d; }
  textarea {
    flex: 1; width: 100%; border: 0; outline: 0; resize: none;
    background: #0f1115; color: #e6e6e6; padding: 16px;
    font: inherit; font-size: 15px; line-height: 1.5;
  }
  #gate {
    position: fixed; inset: 0; background: #0f1115; display: flex;
    align-items: center; justify-content: center; flex-direction: column; gap: 14px;
  }
  #gate input { background: #161b22; color: #e6e6e6; border: 1px solid #30363d; border-radius: 6px; padding: 10px 12px; font: inherit; font-size: 15px; width: 260px; }
  #gate button { background: #238636; color: #fff; border: 0; border-radius: 6px; padding: 10px 18px; font: inherit; cursor: pointer; }
  #gate .err { color: #f85149; font-size: 13px; min-height: 16px; }
</style>
</head>
<body>
  <div id="gate">
    <div style="font-size:18px;letter-spacing:1px;">COPYTO</div>
    <input id="pass" type="password" placeholder="room password" autocomplete="off" />
    <button id="enter">Enter</button>
    <div class="err" id="err"></div>
  </div>

  <header style="display:none" id="bar">
    <span class="dot" id="dot"></span>
    <span id="status">connecting…</span>
    <span class="spacer"></span>
    <span id="chars">0 chars</span>
    <button id="copy">Copy all</button>
    <button id="clear">Clear</button>
  </header>
  <textarea id="pad" style="display:none" placeholder="Shared clipboard — type or paste here" spellcheck="false"></textarea>

<script>
(function () {
  var pad = document.getElementById("pad");
  var bar = document.getElementById("bar");
  var gate = document.getElementById("gate");
  var dot = document.getElementById("dot");
  var status = document.getElementById("status");
  var chars = document.getElementById("chars");
  var errEl = document.getElementById("err");

  var ws = null, rev = 0, applyingRemote = false, password = "", sendTimer = null;

  function connect() {
    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(proto + "//" + location.host + "/ws?p=" + encodeURIComponent(password));

    ws.onopen = function () {
      sessionStorage.setItem("copyto_p", password);
      gate.style.display = "none";
      bar.style.display = "flex";
      pad.style.display = "block";
      dot.className = "dot on";
      status.textContent = "connected";
      pad.focus();
    };
    ws.onclose = function (e) {
      if (e.code === 1006 && gate.style.display !== "none") {
        errEl.textContent = "Wrong password or connection failed.";
        return;
      }
      dot.className = "dot off";
      status.textContent = "reconnecting…";
      setTimeout(connect, 1200);
    };
    ws.onerror = function () {
      if (gate.style.display !== "none") errEl.textContent = "Wrong password or connection failed.";
    };
    ws.onmessage = function (evt) {
      var msg = JSON.parse(evt.data);
      if (msg.type === "init" || msg.type === "update") {
        rev = msg.rev;
        if (pad.value !== msg.text) {
          var s = pad.selectionStart, en = pad.selectionEnd;
          applyingRemote = true;
          pad.value = msg.text;
          applyingRemote = false;
          try { pad.setSelectionRange(s, en); } catch (_) {}
        }
        updateCount();
      }
    };
  }

  function updateCount() { chars.textContent = pad.value.length + " chars"; }

  pad.addEventListener("input", function () {
    if (applyingRemote) return;
    updateCount();
    if (sendTimer) clearTimeout(sendTimer);
    sendTimer = setTimeout(function () {
      if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "update", text: pad.value }));
    }, 120);
  });

  document.getElementById("copy").onclick = function () {
    pad.select();
    navigator.clipboard.writeText(pad.value).catch(function () { document.execCommand("copy"); });
  };
  document.getElementById("clear").onclick = function () {
    pad.value = ""; updateCount();
    if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "update", text: "" }));
  };

  function doEnter() {
    password = document.getElementById("pass").value;
    if (!password) { errEl.textContent = "Enter the password."; return; }
    errEl.textContent = "";
    connect();
  }
  document.getElementById("enter").onclick = doEnter;
  document.getElementById("pass").addEventListener("keydown", function (e) {
    if (e.key === "Enter") doEnter();
  });

  // Auto-reconnect within a session without re-typing the password.
  var saved = sessionStorage.getItem("copyto_p");
  if (saved) { document.getElementById("pass").value = saved; password = saved; connect(); }
})();
</script>
</body>
</html>`;
