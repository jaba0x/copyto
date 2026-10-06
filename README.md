<p align="center">
  <img src="assets/cover.svg" alt="CopyTo — real-time shared clipboard" width="100%">
</p>

A real-time shared clipboard. Open the page on two devices, type or paste on
one, and it appears on the other within a few hundred milliseconds. You can also
send files between devices. Runs on Cloudflare Workers with a Durable Object for
the live sync.

- **One shared pane** — both devices edit the same text; last write wins.
- **Password = room** — the password you type names the room. Use the same one
  on both devices and you share a pane; a different password is a different room.
- **File sharing** — send a file up to 50 MB by button, drag-and-drop, or paste.
  Transfers stream between the connected devices and are never stored on the server.
- **2-person rooms, adjustable** — a room starts capped at 2 people. Any member
  can raise or lower the limit from inside the room.
- **Ephemeral** — each room lives for 1 hour from creation, then clears itself.
  Reconnecting afterward starts a fresh, empty room.

## Security model

The room password is the only credential, so CopyTo is built to keep it from
leaking and to make guessing expensive:

- **The password never leaves the browser.** It is hashed with SHA-256 in the
  client, and only that hash is sent. The hash names the `Room` Durable Object,
  so the same password reaches the same room without the server ever seeing it.
- **The key is not in the URL.** It travels in the WebSocket subprotocol header,
  not a `?query`, so it can't leak through URL logs, browser history or `Referer`.
- **Edge rate limiting.** A Cloudflare rate-limiting binding caps WebSocket
  connection attempts per IP (20 / minute) before they reach the room logic.
- **Per-IP room cap.** An `IpLimiter` Durable Object allows at most 5 distinct
  rooms per IP per hour. Since every wrong password is a different room, this
  throttles guessing to 5 tries/hour from one address. Refusals are logged.
- **Strong passwords.** The gate can generate a 20-character random password
  (~117 bits). A room's secrecy rests on the password being hard to guess, so a
  long random one is the real defense; per-IP limits slow, but do not stop, a
  distributed attempt.

## How it works

- The Worker serves a single HTML page and upgrades `/ws` to a WebSocket. The
  room key arrives in the `Sec-WebSocket-Protocol` header.
- Each `Room` holds the current text, relays text and file chunks to the other
  connected clients, tracks the member limit, and arms a 1-hour alarm on
  creation. When the alarm fires it clears the room and closes connections.
- Files are chunked (~700 KB base64 per message) and relayed through the room to
  the other members, reassembled client-side. Nothing is persisted server-side,
  so a file only reaches devices connected at the time it is sent.

## Setup

```bash
npm install
```

There is no server-wide password to configure — rooms are created on demand by
whatever password a user enters (minimum 6 characters).

## Run locally

```bash
npm run dev
```

Open the printed `localhost` URL in two browser windows, enter the same room
password in each, and type.

## Deploy

```bash
npm run deploy
```

### Custom domain (copy.jaba.ge)

After the first deploy, attach the domain either in the Cloudflare dashboard
(Workers & Pages → your Worker → Settings → Domains & Routes → Add custom
domain) or by uncommenting the `routes` block in `wrangler.toml` and
redeploying. The domain must be on the same Cloudflare account.

## Notes

- Text is capped at ~1 MB per update; files at 50 MB.
- Tuning constants live at the top of `src/worker.js`: `ROOM_TTL_MS` (room
  lifetime), `MAX_ROOMS_PER_IP`, `DEFAULT_MAX_MEMBERS`, and `HARD_MAX_MEMBERS`.
  The edge rate limit is configured in `wrangler.toml` under `[[unsafe.bindings]]`.
- Watch refused attempts live with `npx wrangler tail` (look for `[room-limit]`
  and `[rate-limit]`).
