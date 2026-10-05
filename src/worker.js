// CopyTo — real-time shared clipboard on Cloudflare Workers + Durable Objects.
//
// Rooms are keyed by password: whatever a user types is hashed (SHA-256) and
// that hash names the room's Durable Object, so the same password on two
// machines lands in the same room. Each room lives for 1 hour from creation
// (a DO alarm clears it), then a reconnect starts a fresh one.
//
// Abuse control: each client IP may open at most 5 distinct rooms per hour
// (a per-IP Durable Object tracks this). Rejoining a room the IP already
// opened is free; a 6th new room is refused. Refusals are logged.

const ROOM_TTL_MS = 60 * 60 * 1000; // 1 hour
const MAX_ROOMS_PER_IP = 5;
const MIN_PASSWORD_LEN = 6;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ws") {
      const pass = url.searchParams.get("p") || "";
      if (pass.length < MIN_PASSWORD_LEN) {
        return new Response("Password too short", { status: 400 });
      }
      const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
      const roomKey = await sha256hex(pass);

      // Per-IP room-count check before touching the room.
      const limiter = env.LIMITERS.get(env.LIMITERS.idFromName("ip:" + ip));
      const authRes = await limiter.fetch("https://do/authorize", {
        method: "POST",
        body: JSON.stringify({ roomKey }),
      });
      const auth = await authRes.json();
      if (!auth.ok) {
        console.log(
          `[room-limit] ip=${ip} active=${auth.count} max=${MAX_ROOMS_PER_IP} refused new room`
        );
        return new Response(
          "Room limit reached for your network (max " +
            MAX_ROOMS_PER_IP +
            " per hour).",
          { status: 429 }
        );
      }

      const room = env.ROOMS.get(env.ROOMS.idFromName("room:" + roomKey));
      return room.fetch(request);
    }

    if (url.pathname === "/" || url.pathname === "/index.html") {
      return new Response(PAGE, {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    return new Response("Not found", { status: 404 });
  },
};

async function sha256hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Per-IP room counter. Keeps a map of roomKey -> firstSeen(ms), pruned to the
// last hour, and refuses a new key once the IP holds MAX_ROOMS_PER_IP.
export class IpLimiter {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== "/authorize") return new Response("Not found", { status: 404 });

    const { roomKey } = await request.json();
    const now = Date.now();
    let rooms = (await this.state.storage.get("rooms")) || {};

    for (const k of Object.keys(rooms)) {
      if (now - rooms[k] > ROOM_TTL_MS) delete rooms[k];
    }

    let ok;
    if (roomKey in rooms) {
      ok = true; // already opened by this IP — free to rejoin
    } else if (Object.keys(rooms).length < MAX_ROOMS_PER_IP) {
      rooms[roomKey] = now;
      ok = true;
    } else {
      ok = false;
    }

    await this.state.storage.put("rooms", rooms);
    await this.state.storage.setAlarm(now + ROOM_TTL_MS + 60000);
    return Response.json({ ok, count: Object.keys(rooms).length });
  }

  async alarm() {
    const now = Date.now();
    let rooms = (await this.state.storage.get("rooms")) || {};
    for (const k of Object.keys(rooms)) {
      if (now - rooms[k] > ROOM_TTL_MS) delete rooms[k];
    }
    if (Object.keys(rooms).length === 0) {
      await this.state.storage.deleteAll();
    } else {
      await this.state.storage.put("rooms", rooms);
      await this.state.storage.setAlarm(now + ROOM_TTL_MS);
    }
  }
}

export class Room {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Set();
    this.text = "";
    this.rev = 0;
    this.createdAt = 0;
    this.state.blockConcurrencyWhile(async () => {
      this.text = (await this.state.storage.get("text")) || "";
      this.rev = (await this.state.storage.get("rev")) || 0;
      this.createdAt = (await this.state.storage.get("createdAt")) || 0;
    });
  }

  expiresAt() {
    return this.createdAt ? this.createdAt + ROOM_TTL_MS : 0;
  }

  // Create a fresh room if there isn't a live one (never created, or expired).
  async ensureRoom() {
    const now = Date.now();
    if (!this.createdAt || now - this.createdAt > ROOM_TTL_MS) {
      this.createdAt = now;
      this.text = "";
      this.rev = 0;
      await this.state.storage.put("createdAt", now);
      await this.state.storage.put("text", "");
      await this.state.storage.put("rev", 0);
      await this.state.storage.setAlarm(now + ROOM_TTL_MS);
    }
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected WebSocket", { status: 426 });
    }
    await this.ensureRoom();
    const pair = new WebSocketPair();
    this.handleSession(pair[1]);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  handleSession(ws) {
    ws.accept();
    this.sessions.add(ws);
    ws.send(
      JSON.stringify({ type: "init", text: this.text, rev: this.rev, expiresAt: this.expiresAt() })
    );

    ws.addEventListener("message", async (evt) => {
      let msg;
      try {
        msg = JSON.parse(evt.data);
      } catch {
        return;
      }
      if (msg.type === "update" && typeof msg.text === "string") {
        if (msg.text.length > 1_000_000) return;
        this.text = msg.text;
        this.rev++;
        await this.state.storage.put("text", this.text);
        await this.state.storage.put("rev", this.rev);
        this.broadcast(
          JSON.stringify({
            type: "update",
            text: this.text,
            rev: this.rev,
            expiresAt: this.expiresAt(),
          }),
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

  async alarm() {
    this.broadcast(JSON.stringify({ type: "expired" }));
    for (const ws of this.sessions) {
      try {
        ws.close(1000, "expired");
      } catch {}
    }
    this.sessions.clear();
    this.text = "";
    this.rev = 0;
    this.createdAt = 0;
    await this.state.storage.deleteAll();
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
  header .ttl { color: #9fb2c8; font-variant-numeric: tabular-nums; }
  header button { background: #21262d; color: #e6e6e6; border: 1px solid #30363d; border-radius: 6px; padding: 5px 10px; font: inherit; font-size: 12px; cursor: pointer; }
  header button:hover { background: #30363d; }
  textarea {
    flex: 1; width: 100%; border: 0; outline: 0; resize: none;
    background: #0f1115; color: #e6e6e6; padding: 16px;
    font: inherit; font-size: 15px; line-height: 1.5;
  }
  textarea:disabled { opacity: .6; }
  #gate {
    position: fixed; inset: 0; background: #0f1115; display: flex;
    align-items: center; justify-content: center; flex-direction: column; gap: 14px; padding: 20px;
  }
  #gate .logo { width: 76px; height: 76px; }
  #gate .mark { font-size: 18px; letter-spacing: 2px; margin-top: 2px; }
  #gate input { background: #161b22; color: #e6e6e6; border: 1px solid #30363d; border-radius: 6px; padding: 10px 12px; font: inherit; font-size: 15px; width: 280px; }
  #gate button { background: #238636; color: #fff; border: 0; border-radius: 6px; padding: 10px 18px; font: inherit; cursor: pointer; }
  #gate .hint { color: #6e7b8c; font-size: 12px; }
  #gate .err { color: #f85149; font-size: 13px; min-height: 16px; text-align: center; max-width: 320px; }
  #gate a.repo { color: #2dd4bf; font-size: 12px; text-decoration: none; opacity: .85; margin-top: 6px; }
  #gate a.repo:hover { text-decoration: underline; }
</style>
</head>
<body>
  <div id="gate">
    <svg class="logo" viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg" aria-label="CopyTo logo">
      <defs>
        <linearGradient id="lbg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0f1b2d"/><stop offset="1" stop-color="#16263f"/></linearGradient>
        <linearGradient id="lscr" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2dd4bf"/><stop offset="1" stop-color="#14a597"/></linearGradient>
      </defs>
      <rect width="256" height="256" rx="56" fill="url(#lbg)"/>
      <rect x="26" y="80" width="84" height="96" rx="16" fill="url(#lscr)"/>
      <rect x="40" y="100" width="56" height="8" rx="4" fill="#0f1b2d" opacity=".5"/>
      <rect x="40" y="118" width="44" height="8" rx="4" fill="#0f1b2d" opacity=".5"/>
      <rect x="40" y="136" width="52" height="8" rx="4" fill="#0f1b2d" opacity=".5"/>
      <rect x="146" y="80" width="84" height="96" rx="16" fill="url(#lscr)"/>
      <rect x="160" y="100" width="56" height="8" rx="4" fill="#0f1b2d" opacity=".5"/>
      <rect x="160" y="118" width="44" height="8" rx="4" fill="#0f1b2d" opacity=".5"/>
      <rect x="160" y="136" width="52" height="8" rx="4" fill="#0f1b2d" opacity=".5"/>
      <rect x="110" y="124" width="36" height="8" rx="4" fill="#2dd4bf" opacity=".35"/>
    </svg>
    <div class="mark">COPYTO</div>
    <input id="pass" type="password" placeholder="room password (6+ chars)" autocomplete="off" />
    <button id="enter">Enter</button>
    <div class="hint">Same password = same room. Rooms last 1 hour.</div>
    <div class="err" id="err"></div>
    <a class="repo" href="https://github.com/jaba0x/copyto" target="_blank" rel="noopener">github.com/jaba0x/copyto</a>
  </div>

  <header style="display:none" id="bar">
    <span class="dot" id="dot"></span>
    <span id="status">connecting…</span>
    <span class="spacer"></span>
    <span class="ttl" id="ttl"></span>
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
  var ttl = document.getElementById("ttl");
  var errEl = document.getElementById("err");

  var ws = null, rev = 0, applyingRemote = false, password = "", sendTimer = null;
  var expiresAt = 0, ttlTimer = null, expired = false, stop = false;

  function fmt(ms) {
    if (ms < 0) ms = 0;
    var s = Math.floor(ms / 1000), m = Math.floor(s / 60);
    s = s % 60;
    return "expires in " + m + ":" + (s < 10 ? "0" + s : s);
  }
  function tick() {
    if (!expiresAt) { ttl.textContent = ""; return; }
    ttl.textContent = fmt(expiresAt - Date.now());
  }

  function connect() {
    var proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(proto + "//" + location.host + "/ws?p=" + encodeURIComponent(password));

    ws.onopen = function () {
      sessionStorage.setItem("copyto_p", password);
      gate.style.display = "none";
      bar.style.display = "flex";
      pad.style.display = "block";
      pad.disabled = false;
      dot.className = "dot on";
      status.textContent = "connected";
      pad.focus();
      if (ttlTimer) clearInterval(ttlTimer);
      ttlTimer = setInterval(tick, 1000);
    };
    ws.onclose = function (e) {
      if (stop) return;
      if (gate.style.display !== "none") {
        errEl.textContent = "Couldn't open the room. Either your network's limit of 5 rooms/hour was reached, or the connection failed.";
        return;
      }
      dot.className = "dot off";
      status.textContent = "reconnecting…";
      setTimeout(connect, 1200);
    };
    ws.onerror = function () {
      if (gate.style.display !== "none") errEl.textContent = "Couldn't open the room. Check the password length (6+), or try again.";
    };
    ws.onmessage = function (evt) {
      var msg = JSON.parse(evt.data);
      if (msg.type === "expired") {
        expired = true; stop = true;
        sessionStorage.removeItem("copyto_p");
        dot.className = "dot off";
        status.textContent = "room expired — reload to start a new one";
        ttl.textContent = "";
        pad.disabled = true;
        if (ttlTimer) clearInterval(ttlTimer);
        try { ws.close(); } catch (_) {}
        return;
      }
      if (msg.type === "init" || msg.type === "update") {
        rev = msg.rev;
        expiresAt = msg.expiresAt || 0;
        tick();
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
    if (password.length < 6) { errEl.textContent = "Use at least 6 characters."; return; }
    errEl.textContent = "";
    stop = false; expired = false;
    connect();
  }
  document.getElementById("enter").onclick = doEnter;
  document.getElementById("pass").addEventListener("keydown", function (e) {
    if (e.key === "Enter") doEnter();
  });

  var saved = sessionStorage.getItem("copyto_p");
  if (saved) { document.getElementById("pass").value = saved; password = saved; connect(); }
})();
</script>
</body>
</html>`;
