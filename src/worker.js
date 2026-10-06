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
const DEFAULT_MAX_MEMBERS = 2;  // a room starts as a 2-person room
const HARD_MAX_MEMBERS = 10;    // ceiling even after members raise the limit

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
    this.maxMembers = DEFAULT_MAX_MEMBERS;
    this.state.blockConcurrencyWhile(async () => {
      this.text = (await this.state.storage.get("text")) || "";
      this.rev = (await this.state.storage.get("rev")) || 0;
      this.createdAt = (await this.state.storage.get("createdAt")) || 0;
      this.maxMembers = (await this.state.storage.get("maxMembers")) || DEFAULT_MAX_MEMBERS;
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
      this.maxMembers = DEFAULT_MAX_MEMBERS;
      await this.state.storage.put("createdAt", now);
      await this.state.storage.put("text", "");
      await this.state.storage.put("rev", 0);
      await this.state.storage.put("maxMembers", DEFAULT_MAX_MEMBERS);
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
    // Capacity: a room holds at most maxMembers people (default 2). Members can
    // raise the limit from inside the room.
    if (this.sessions.size >= this.maxMembers) {
      try { ws.send(JSON.stringify({ type: "full", max: this.maxMembers })); } catch {}
      try { ws.close(4001, "room full"); } catch {}
      return;
    }
    this.sessions.add(ws);
    ws.send(
      JSON.stringify({
        type: "init",
        text: this.text,
        rev: this.rev,
        expiresAt: this.expiresAt(),
        members: this.sessions.size,
        max: this.maxMembers,
      })
    );
    this.broadcastMembers();

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
        return;
      }
      // File transfer: relay chunks to the other clients, never stored server-side.
      if (msg.type === "file-start" || msg.type === "file-chunk" || msg.type === "file-end") {
        if (evt.data.length > 1_000_000) return; // per-message guard (chunks are ~700 KB)
        this.broadcast(evt.data, ws);
        return;
      }
      // Any member may raise the room's member limit by one.
      if (msg.type === "raise-limit") {
        if (this.maxMembers < HARD_MAX_MEMBERS) {
          this.maxMembers++;
          await this.state.storage.put("maxMembers", this.maxMembers);
          this.broadcastMembers();
        }
        return;
      }
    });

    const close = () => { this.sessions.delete(ws); this.broadcastMembers(); };
    ws.addEventListener("close", close);
    ws.addEventListener("error", close);
  }

  broadcastMembers() {
    this.broadcast(JSON.stringify({ type: "members", count: this.sessions.size, max: this.maxMembers }));
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
    color: #e6e6e6; min-height: 100dvh;
    display: flex; flex-direction: column;
    background:
      radial-gradient(120% 70% at 85% 0%, rgba(45,212,191,.08), transparent 48%),
      linear-gradient(160deg, #0f1b2d 0%, #16263f 100%);
  }
  header {
    padding: 11px 18px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; row-gap: 8px;
    border-bottom: 1px solid rgba(255,255,255,.08); font-size: 13px;
    background: rgba(13,22,36,.5);
    backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
  }
  header .members {
    display: inline-flex; align-items: center; gap: 7px;
    color: #8ba0b8; font-variant-numeric: tabular-nums;
  }
  header .members .count { color: #cfe0ee; }
  header button.plus {
    width: 24px; height: 24px; padding: 0; display: grid; place-items: center;
    font-size: 15px; line-height: 1; border-radius: 7px;
  }
  header button.plus:disabled { opacity: .35; cursor: default; }
  header button.danger { color: #ffb4ad; border-color: rgba(248,81,73,.35); }
  header button.danger:hover { background: rgba(248,81,73,.14); border-color: rgba(248,81,73,.6); }
  #copyright {
    position: fixed; right: 14px; bottom: 12px; z-index: 30;
    font-size: 11px; color: #5f7084;
    background: rgba(13,22,36,.6); border: 1px solid rgba(255,255,255,.07);
    border-radius: 8px; padding: 5px 10px;
    backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
  }
  #copyright a { color: #2dd4bf; text-decoration: none; }
  #copyright a:hover { text-decoration: underline; }
  header .brand { display: flex; align-items: center; gap: 8px; font-weight: 700; color: #eef3f9; letter-spacing: -.3px; }
  header .brand b { color: #2dd4bf; font-weight: 700; }
  header .brand svg { width: 20px; height: 20px; display: block; }
  header .dot { width: 9px; height: 9px; border-radius: 50%; background: #e0b341; transition: background .2s; }
  header .dot.on { background: #2dd4bf; box-shadow: 0 0 8px rgba(45,212,191,.7); }
  header .dot.off { background: #f85149; }
  header #status { color: #8ba0b8; }
  header .spacer { flex: 1; }
  header .ttl { color: #8ba0b8; font-variant-numeric: tabular-nums; }
  header #chars { color: #5f7084; }
  header button {
    background: rgba(255,255,255,.05); color: #cfe0ee; border: 1px solid rgba(255,255,255,.12);
    border-radius: 8px; padding: 6px 11px; font: inherit; font-size: 12px; cursor: pointer;
    transition: background .15s, border-color .15s;
  }
  header button:hover { background: rgba(255,255,255,.1); border-color: rgba(45,212,191,.4); }
  header button:active { transform: scale(.97); }
  main { flex: 1; display: flex; padding: 16px 18px; min-height: 0; }
  textarea {
    flex: 1; width: 100%; border: 1px solid rgba(255,255,255,.1); outline: 0; resize: none;
    background: rgba(8,15,26,.55); color: #eef3f9; padding: 16px; border-radius: 14px;
    font: inherit; font-size: 15px; line-height: 1.6;
    transition: border-color .15s, box-shadow .15s;
  }
  textarea:focus { border-color: rgba(45,212,191,.55); box-shadow: 0 0 0 3px rgba(45,212,191,.16); }
  textarea:disabled { opacity: .6; }
  /* drag-over state */
  body.dragging textarea { border-color: #2dd4bf; box-shadow: 0 0 0 3px rgba(45,212,191,.28); }
  #drophint {
    position: fixed; inset: 0; z-index: 40; display: none;
    align-items: center; justify-content: center; pointer-events: none;
    background: rgba(9,16,26,.55); backdrop-filter: blur(3px);
    color: #2dd4bf; font-size: 18px; letter-spacing: .02em;
  }
  body.dragging #drophint { display: flex; }
  /* attachment strip */
  #files {
    display: none; flex-wrap: wrap; gap: 8px;
    padding: 0 18px 16px;
  }
  #files.show { display: flex; }
  .chip {
    display: flex; flex-direction: column; gap: 7px; width: 260px;
    background: rgba(13,22,36,.7); border: 1px solid rgba(255,255,255,.1);
    border-radius: 10px; padding: 9px 11px; font-size: 12.5px;
  }
  .chip .row { display: flex; align-items: center; gap: 9px; }
  .chip .ic { width: 15px; height: 15px; color: #2dd4bf; flex: none; }
  .chip .ic.out { color: #8ba0b8; }
  .chip .nm { flex: 1; color: #eef3f9; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .chip .meta { color: #5f7084; flex: none; font-variant-numeric: tabular-nums; }
  .chip a.dl { color: #2dd4bf; text-decoration: none; flex: none; font-weight: 700; }
  .chip a.dl:hover { text-decoration: underline; }
  .chip .bar { height: 4px; border-radius: 999px; background: rgba(255,255,255,.1); overflow: hidden; }
  .chip .bar .fill { height: 100%; width: 0%; background: #2dd4bf; border-radius: 999px; transition: width .15s linear; }
  .chip.done .bar { display: none; }
  /* --- login gate: CopyTo brand (navy gradient + locked teal accent) --- */
  #gate {
    position: fixed; inset: 0; display: flex;
    align-items: center; justify-content: center; padding: 24px;
    background:
      radial-gradient(120% 90% at 18% 0%, rgba(45,212,191,.14), transparent 46%),
      linear-gradient(140deg, #0f1b2d 0%, #16263f 100%);
  }
  #gate .bg { position: absolute; inset: 0; overflow: hidden; pointer-events: none; z-index: 0; }
  #gate .bg .line {
    position: absolute; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, rgba(45,212,191,.10) 20%, rgba(45,212,191,.10) 80%, transparent);
  }
  #gate .bg .line::after {
    content: ""; position: absolute; top: 50%; left: 0; width: 120px; height: 2px;
    transform: translate(-140px, -50%);
    background: linear-gradient(90deg, transparent, rgba(45,212,191,.9), transparent);
    box-shadow: 0 0 10px 1px rgba(45,212,191,.55);
    animation: pkt-fly var(--dur, 9s) linear var(--delay, 0s) infinite;
  }
  @keyframes pkt-fly {
    0% { transform: translate(-140px, -50%); }
    100% { transform: translate(calc(100vw + 140px), -50%); }
  }
  #gate .card {
    position: relative; z-index: 1;
    width: 100%; max-width: 360px;
    display: flex; flex-direction: column; align-items: center; gap: 18px;
    padding: 34px 30px 26px;
    background: rgba(13, 22, 36, .66);
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 16px;
    box-shadow: inset 0 1px 0 rgba(255,255,255,.07), 0 24px 70px rgba(0,0,0,.45);
    backdrop-filter: blur(14px) saturate(140%);
    -webkit-backdrop-filter: blur(14px) saturate(140%);
  }
  #gate .logo { width: 64px; height: 64px; }
  #gate .head { text-align: center; }
  #gate .mark { font-size: 24px; font-weight: 700; letter-spacing: -.5px; color: #eef3f9; }
  #gate .mark b { color: #2dd4bf; font-weight: 700; }
  #gate .sub { margin-top: 4px; font-size: 12.5px; color: #8ba0b8; }
  #gate .field { width: 100%; display: flex; flex-direction: column; gap: 7px; }
  #gate label { font-size: 11px; letter-spacing: .04em; text-transform: uppercase; color: #8ba0b8; }
  #gate .input-wrap { position: relative; }
  #gate input {
    width: 100%; background: rgba(8,15,26,.7); color: #eef3f9;
    border: 1px solid rgba(255,255,255,.12); border-radius: 10px;
    padding: 12px 44px 12px 13px; font: inherit; font-size: 15px;
    transition: border-color .15s, box-shadow .15s;
  }
  #gate input::placeholder { color: #5f7084; }
  #gate input:focus {
    outline: 0; border-color: #2dd4bf;
    box-shadow: 0 0 0 3px rgba(45,212,191,.22);
  }
  #gate .toggle {
    position: absolute; right: 6px; top: 50%; transform: translateY(-50%);
    width: 32px; height: 32px; display: grid; place-items: center;
    background: transparent; border: 0; border-radius: 8px; cursor: pointer;
    color: #8ba0b8; padding: 0;
  }
  #gate .toggle:hover { color: #cfe0ee; background: rgba(255,255,255,.06); }
  #gate .toggle svg { width: 18px; height: 18px; display: block; }
  #gate button.enter {
    width: 100%; background: #2dd4bf; color: #082018; font-weight: 700;
    border: 0; border-radius: 10px; padding: 12px 18px; font: inherit; font-weight: 700;
    cursor: pointer; transition: background .15s, transform .06s;
  }
  #gate button.enter:hover { background: #45e0cd; }
  #gate button.enter:active { transform: scale(.985); }
  #gate .hint { font-size: 12px; color: #7488a0; text-align: center; line-height: 1.5; }
  #gate .err { color: #ff6b63; font-size: 12.5px; min-height: 16px; text-align: center; line-height: 1.45; }
  #gate .foot { display: flex; align-items: center; gap: 8px; font-size: 11.5px; color: #5f7084; }
  #gate .foot a { color: #2dd4bf; text-decoration: none; opacity: .9; }
  #gate .foot a:hover { text-decoration: underline; }
  #gate .foot .sep { opacity: .4; }
  #gate .card { animation: gate-in .5s cubic-bezier(.16,1,.3,1) both; }
  @keyframes gate-in { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: none; } }
  .pkt { animation: pkt-move 2.6s cubic-bezier(.45,0,.55,1) infinite; }
  .pkt.b { animation-delay: 1.3s; }
  @keyframes pkt-move {
    0% { transform: translateX(0); opacity: 0; }
    15% { opacity: 1; } 45% { opacity: 1; }
    55%, 100% { transform: translateX(44px); opacity: 0; }
  }
  @media (prefers-reduced-motion: reduce) {
    #gate .card { animation: none; }
    .pkt { animation: none; opacity: 1; }
    #gate .bg .line::after { animation: none; opacity: 0; }
  }
</style>
</head>
<body>
  <div id="gate">
    <div class="bg" aria-hidden="true">
      <div class="line" style="top:14%; --dur:11s; --delay:0s"></div>
      <div class="line" style="top:29%; --dur:8s; --delay:2.4s"></div>
      <div class="line" style="top:43%; --dur:13s; --delay:1.2s"></div>
      <div class="line" style="top:61%; --dur:9.5s; --delay:3.6s"></div>
      <div class="line" style="top:74%; --dur:12s; --delay:.8s"></div>
      <div class="line" style="top:88%; --dur:7.5s; --delay:4.2s"></div>
    </div>
    <div class="card">
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
        <circle class="pkt" cx="112" cy="128" r="6" fill="#ffd35a"/>
        <circle class="pkt b" cx="112" cy="128" r="6" fill="#ffd35a"/>
      </svg>
      <div class="head">
        <div class="mark">Copy<b>To</b></div>
        <div class="sub">Real-time shared clipboard</div>
      </div>
      <div class="field">
        <label for="pass">Room password</label>
        <div class="input-wrap">
          <input id="pass" type="password" placeholder="6+ characters" autocomplete="off" autocapitalize="off" spellcheck="false" />
          <button type="button" class="toggle" id="toggle" aria-label="Show password">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>
      </div>
      <button class="enter" id="enter">Enter room</button>
      <div class="err" id="err"></div>
      <div class="hint">Type the same password on both devices to share a room. Rooms last one hour.</div>
      <div class="foot">
        <a href="https://github.com/jaba0x/copyto" target="_blank" rel="noopener">github.com/jaba0x/copyto</a>
        <span class="sep">/</span>
        <span>copy.jaba.ge</span>
      </div>
    </div>
  </div>

  <header style="display:none" id="bar">
    <span class="brand">
      <svg viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <rect width="256" height="256" rx="56" fill="#0f1b2d"/>
        <rect x="26" y="80" width="84" height="96" rx="16" fill="#2dd4bf"/>
        <rect x="146" y="80" width="84" height="96" rx="16" fill="#2dd4bf"/>
        <rect x="110" y="124" width="36" height="8" rx="4" fill="#2dd4bf" opacity=".4"/>
      </svg>
      <span class="wm">Copy<b>To</b></span>
    </span>
    <span class="dot" id="dot"></span>
    <span id="status">connecting…</span>
    <span class="members" title="People in this room">
      <span class="count" id="mcount">1</span>/<span id="mmax">2</span>
      <button class="plus" id="raise" title="Allow one more person">+</button>
    </span>
    <span class="spacer"></span>
    <span class="ttl" id="ttl"></span>
    <span id="chars">0 chars</span>
    <button id="attach">Attach</button>
    <button id="copy">Copy all</button>
    <button id="clear">Clear</button>
    <button id="disconnect" class="danger">Disconnect</button>
    <input id="fileInput" type="file" style="display:none" />
  </header>
  <main style="display:none" id="main">
    <textarea id="pad" placeholder="Shared clipboard. Type or paste here. Drop a file to share it (max 50 MB)." spellcheck="false"></textarea>
  </main>
  <div id="files"></div>
  <div id="drophint">Drop to share (max 50 MB)</div>
  <div id="copyright" style="display:none">© 2026 Jaba Macharashvili · <a href="https://github.com/jaba0x/copyto" target="_blank" rel="noopener">source</a></div>

<script>
(function () {
  var pad = document.getElementById("pad");
  var bar = document.getElementById("bar");
  var mainEl = document.getElementById("main");
  var gate = document.getElementById("gate");
  var dot = document.getElementById("dot");
  var status = document.getElementById("status");
  var chars = document.getElementById("chars");
  var ttl = document.getElementById("ttl");
  var errEl = document.getElementById("err");
  var filesEl = document.getElementById("files");
  var mcount = document.getElementById("mcount");
  var mmax = document.getElementById("mmax");
  var raiseBtn = document.getElementById("raise");
  var copyrightEl = document.getElementById("copyright");

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
        status.textContent = "room expired. reload to start a new one";
        ttl.textContent = "";
        pad.disabled = true;
        if (ttlTimer) clearInterval(ttlTimer);
        try { ws.close(); } catch (_) {}
        return;
      }
      if (msg.type === "init") {
        // Accepted into the room: now reveal it.
        gate.style.display = "none";
        bar.style.display = "flex";
        mainEl.style.display = "flex";
        copyrightEl.style.display = "block";
        pad.disabled = false;
        dot.className = "dot on";
        status.textContent = "connected";
        if (typeof msg.members === "number") mcount.textContent = msg.members;
        if (typeof msg.max === "number") { mmax.textContent = msg.max; raiseBtn.disabled = msg.max >= 10; }
        pad.focus();
        if (ttlTimer) clearInterval(ttlTimer);
        ttlTimer = setInterval(tick, 1000);
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
        return;
      }
      if (msg.type === "file-start") {
        incoming[msg.id] = { name: msg.name, mime: msg.mime, size: msg.size, total: msg.total, parts: [], got: 0 };
        addChip(msg.id, msg.name, msg.size, "in");
        return;
      }
      if (msg.type === "file-chunk") {
        var inc = incoming[msg.id];
        if (!inc) return;
        inc.parts[msg.i] = msg.data; inc.got++;
        setChipPct(msg.id, Math.round((inc.got / inc.total) * 100));
        return;
      }
      if (msg.type === "file-end") {
        var f = incoming[msg.id];
        if (!f) return;
        var href = "data:" + (f.mime || "application/octet-stream") + ";base64," + f.parts.join("");
        setChipDownload(msg.id, href, f.name);
        delete incoming[msg.id];
        return;
      }
      if (msg.type === "members") {
        mcount.textContent = msg.count;
        mmax.textContent = msg.max;
        raiseBtn.disabled = msg.max >= 10;
        return;
      }
      if (msg.type === "full") {
        stop = true;
        try { ws.close(); } catch (_) {}
        sessionStorage.removeItem("copyto_p");
        gate.style.display = "flex";
        bar.style.display = "none";
        mainEl.style.display = "none";
        copyrightEl.style.display = "none";
        errEl.textContent = "Room is full (" + msg.max + "/" + msg.max + "). Ask someone inside to allow one more.";
        return;
      }
    };
  }

  // ---- attachments (chunked relay over the WebSocket, max 50 MB) ----
  var MAX_FILE = 50 * 1024 * 1024;
  var CHUNK = 700 * 1024;              // base64 chars per chunk, under the 1 MB WS message limit
  var BACKPRESSURE = 4 * 1024 * 1024;  // pause sending while the socket buffer is above this
  var incoming = {};

  function fmtSize(n) {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(1) + " MB";
  }
  function fileIcon(dir) {
    return '<svg class="ic ' + dir + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>';
  }
  // dir: "in" (downloading) or "out" (uploading)
  function addChip(id, name, size, dir) {
    filesEl.classList.add("show");
    var el = document.createElement("div");
    el.className = "chip"; el.id = "chip-" + id;
    el.innerHTML =
      '<div class="row">' + fileIcon(dir) +
        '<span class="nm"></span>' +
        '<span class="meta">0%</span>' +
      '</div>' +
      '<div class="bar"><div class="fill"></div></div>';
    el.querySelector(".nm").textContent = name;
    el._size = size;
    filesEl.appendChild(el);
    return el;
  }
  function setChipPct(id, pct) {
    var el = document.getElementById("chip-" + id); if (!el) return;
    el.querySelector(".fill").style.width = pct + "%";
    var m = el.querySelector(".meta"); if (m) m.textContent = pct + "%";
  }
  function finishChip(id, href, name) {
    var el = document.getElementById("chip-" + id); if (!el) return;
    el.classList.add("done");
    el.querySelector(".meta").textContent = fmtSize(el._size || 0);
    var row = el.querySelector(".row");
    var a = document.createElement("a");
    a.className = "dl"; a.href = href; a.download = name; a.textContent = "Save";
    row.appendChild(a);
  }
  function setChipDownload(id, href, name) { finishChip(id, href, name); }

  function sendFile(file) {
    if (!file) return;
    if (!ws || ws.readyState !== 1) return;
    if (file.size > MAX_FILE) { flashStatus("File too large (max 50 MB)"); return; }
    var reader = new FileReader();
    reader.onload = function () {
      var url = String(reader.result);
      var b64 = url.slice(url.indexOf(",") + 1);
      var id = Math.random().toString(36).slice(2, 10);
      var total = Math.ceil(b64.length / CHUNK) || 1;
      addChip(id, file.name, file.size, "out");
      ws.send(JSON.stringify({ type: "file-start", id: id, name: file.name, mime: file.type || "application/octet-stream", size: file.size, total: total }));
      var i = 0;
      function pump() {
        if (!ws || ws.readyState !== 1) return; // disconnected mid-send
        while (i < total) {
          if (ws.bufferedAmount > BACKPRESSURE) { setTimeout(pump, 40); return; }
          ws.send(JSON.stringify({ type: "file-chunk", id: id, i: i, data: b64.slice(i * CHUNK, (i + 1) * CHUNK) }));
          i++;
          setChipPct(id, Math.round((i / total) * 100));
          if (i % 3 === 0) { setTimeout(pump, 0); return; } // yield so the bar paints
        }
        ws.send(JSON.stringify({ type: "file-end", id: id }));
        finishChip(id, url, file.name); // keep a local Save link for the sender too
      }
      pump();
    };
    reader.readAsDataURL(file);
  }
  function flashStatus(t) {
    var prev = status.textContent; status.textContent = t;
    setTimeout(function () { if (status.textContent === t) status.textContent = prev; }, 2500);
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

  raiseBtn.onclick = function () {
    if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "raise-limit" }));
  };
  document.getElementById("disconnect").onclick = function () {
    stop = true;
    try { ws && ws.close(); } catch (_) {}
    sessionStorage.removeItem("copyto_p");
    if (ttlTimer) clearInterval(ttlTimer);
    bar.style.display = "none";
    mainEl.style.display = "none";
    copyrightEl.style.display = "none";
    filesEl.innerHTML = ""; filesEl.classList.remove("show");
    pad.value = ""; updateCount();
    errEl.textContent = "";
    document.getElementById("pass").value = "";
    gate.style.display = "flex";
    document.getElementById("pass").focus();
  };

  var fileInput = document.getElementById("fileInput");
  document.getElementById("attach").onclick = function () { fileInput.click(); };
  fileInput.onchange = function () {
    if (fileInput.files && fileInput.files[0]) sendFile(fileInput.files[0]);
    fileInput.value = "";
  };

  // drag & drop onto the page (only while in a room)
  var dragDepth = 0;
  window.addEventListener("dragenter", function (e) {
    if (gate.style.display !== "none") return;
    e.preventDefault(); dragDepth++; document.body.classList.add("dragging");
  });
  window.addEventListener("dragover", function (e) { if (gate.style.display === "none") e.preventDefault(); });
  window.addEventListener("dragleave", function () {
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) document.body.classList.remove("dragging");
  });
  window.addEventListener("drop", function (e) {
    if (gate.style.display !== "none") return;
    e.preventDefault(); dragDepth = 0; document.body.classList.remove("dragging");
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) sendFile(e.dataTransfer.files[0]);
  });
  // paste a file straight into the pad
  pad.addEventListener("paste", function (e) {
    var items = e.clipboardData && e.clipboardData.files;
    if (items && items.length) { e.preventDefault(); sendFile(items[0]); }
  });

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

  var passEl = document.getElementById("pass");
  var toggleEl = document.getElementById("toggle");
  if (toggleEl) toggleEl.onclick = function () {
    var showing = passEl.type === "text";
    passEl.type = showing ? "password" : "text";
    toggleEl.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    toggleEl.style.color = showing ? "" : "#2dd4bf";
    passEl.focus();
  };

  var saved = sessionStorage.getItem("copyto_p");
  if (saved) { document.getElementById("pass").value = saved; password = saved; connect(); }
})();
</script>
</body>
</html>`;
