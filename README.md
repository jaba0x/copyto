<p align="center">
  <img src="assets/cover.svg" alt="CopyTo — real-time shared clipboard" width="100%">
</p>

A real-time shared clipboard. Open the page on two machines, type or paste on
one, and it appears on the other within a few hundred milliseconds. Runs on
Cloudflare Workers with a Durable Object for the live sync.

- **One shared pane** — both machines edit the same text; last write wins.
- **Password = room** — the password you type names the room. Use the same one
  on both machines and you share a pane; a different password is a different room.
- **Ephemeral** — each room lives for 1 hour from creation, then clears itself.
  Reconnecting afterward starts a fresh, empty room.
- **Abuse-limited** — each client IP may open at most 5 distinct rooms per hour.

## How it works

- The Worker serves a single HTML page and upgrades `/ws` to a WebSocket.
- The password is hashed (SHA-256) and that hash names a `Room` Durable Object,
  so the same password reaches the same room. The raw password is never used as
  an identifier or stored on the server.
- Each `Room` holds the current text, fans updates out to every connected
  client, and arms a 1-hour alarm on creation. When the alarm fires it clears
  the text and closes connections.
- Before a room is reached, a per-IP `IpLimiter` Durable Object checks how many
  distinct rooms that IP has opened in the last hour. Rejoining a room the IP
  already opened is free; a sixth new room is refused (HTTP 429) and logged.

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

- Text is capped at ~1 MB per update.
- A room's secrecy rests entirely on the password being hard to guess. Anyone
  who enters the same password joins the same room, so prefer a long, random
  one for anything sensitive. The per-IP limit of 5 rooms/hour slows guessing
  from a single address but does not stop a distributed attempt.
- Tuning constants live at the top of `src/worker.js`: `ROOM_TTL_MS` (room
  lifetime), `MAX_ROOMS_PER_IP`, and `MIN_PASSWORD_LEN`.
- Watch refused attempts live with `npx wrangler tail` (look for `[room-limit]`).
