# Architecture

A map for reading the code. If you open `miner.c` cold, start here.

- [Big picture](#big-picture)
- [Thread model](#thread-model)
- [Startup sequence](#startup-sequence)
- [Data flow: from JSON to a hash](#data-flow-from-json-to-a-hash)
- [The block header and the midstate split](#the-block-header-and-the-midstate-split)
- [The hot loop](#the-hot-loop)
- [Hashing engines](#hashing-engines)
- [Targets, difficulty and byte order](#targets-difficulty-and-byte-order)
- [Stratum conversation](#stratum-conversation)
- [Concurrency rules](#concurrency-rules)
- [Verification](#verification)
- [Failure handling](#failure-handling)
- [Where to start reading](#where-to-start-reading)
- [Limitations and ideas](#limitations-and-ideas)

---

## Big picture

A Stratum v1 client that receives block templates from a pool, builds block
headers, and searches for a nonce whose double-SHA256 is below a target.

The program is deliberately split into two very different halves:

| Half | Runs | Cost | Language |
|---|---|---|---|
| Protocol, job assembly, UI | once per message / per job | irrelevant | plain C |
| Hashing | billions of times per second | everything | asm / AVX2 / C |

All optimisation effort belongs in the second half. The first half is written
for clarity, not speed — a naive JSON parser and a textbook SHA-256 are fine
there because they run once per job, not once per nonce.

---

## Thread model

```
                    +------------------------------+
                    |         main thread          |
                    |  recv() from the pool        |
                    |  parse JSON                  |
                    |  update Shared under mutex   |
                    |  drain the event queue       |
                    |  print status and events     |
                    +------------------------------+
                        ^                    |
         event queue    |                    |  Shared { job, target, best }
         (g_ev_mtx)     |                    v  (g_state_mtx)
        +-----------+-----------+-----------+-----------+
        | worker 0  | worker 1  | worker 2  | worker N-1|
        |  hashing  |  hashing  |  hashing  |  hashing  |
        +-----------+-----------+-----------+-----------+
                        |
                        |  mining.submit  (g_send_mtx)
                        v
                       pool
```

**Only the main thread prints.** The status line is redrawn in place with `\r`;
two concurrent printers would shred it. Workers push text into a queue instead.

**Workers write to the socket directly.** TCP is full duplex, so sending a share
from a worker while main is reading is safe; a mutex serialises the writes and
protects the socket handle across reconnects.

**Benchmark threads** exist only during startup tuning and are joined before
mining begins.

| Mutex | Protects | Held for |
|---|---|---|
| `g_state_mtx` | `Shared`: job, target, extranonce1, best | a struct copy, once per batch |
| `g_send_mtx` | `g_sock` and socket writes | one `send()` |
| `g_ev_mtx` | worker → main event list | pointer swap |

---

## Startup sequence

```
main()
 |-- parse CLI; -a and -p are mandatory (no built-in defaults)
 |-- print CPU brand and features
 |-- [-d MIN] delay loop, CPU completely idle
 |-- engine selection
 |     |-- -e shani|avx2|scalar  -> use it, no benchmark
 |     +-- auto -> benchmark every available engine on N threads, pick fastest
 |-- selftest against known-answer vectors  --(mismatch)--> exit(2)
 |-- spawn N mining workers
 +-- reconnect loop:
       connect -> subscribe -> authorize -> read loop -> on error, retry in 5 s
```

The delay sits **before** tuning on purpose. When the miner is autostarted with
Windows, the first minute is full of boot-time load; benchmarking then would
produce a distorted ranking. During the delay the process only sleeps.

---

## Data flow: from JSON to a hash

A `mining.notify` does **not** contain a header. It contains the parts to build
one, split around the extranonce so that each miner can vary its own search
space without asking the pool.

```
mining.notify
   |
   v
Job { job_id, prevhash, coinb1, coinb2, branches[], version, nbits, ntime }
   |
   |  once per extranonce2 (i.e. per ~4 billion hashes, or on a new job)
   v
coinbase = coinb1 || extranonce1 || extranonce2 || coinb2
   |
   v
mr = SHA256d(coinbase)
for each branch b:   mr = SHA256d(mr || b)          <- merkle fold
   |
   v
header[80] = version || prevhash || mr || ntime || nbits || nonce
   |
   |-- header[0..63]  --> midstate()      (computed once)
   +-- header[64..79] --> tail[16]
                            |
                            |  per nonce  <- THE HOT LOOP
                            v
                  sha256d_tail(mid, tail) --> 32-byte hash
                            |
                            |-- hash <= share target   -> mining.submit
                            +-- hash <= network target -> BLOCK FOUND
```

Notes:

- `extranonce1` is assigned **per connection** by the pool. Two machines with
  the same worker name still search disjoint spaces.
- Merkle branches arrive in internal byte order and are concatenated as-is.
- An empty branch list means the block holds only the coinbase; the merkle root
  is then the coinbase txid itself. The fold loop simply does not execute.

---

## The block header and the midstate split

| Offset | Size | Field | Endianness in the header |
|---:|---:|---|---|
| 0 | 4 | version | little |
| 4 | 32 | prev_block_hash | internal (little) |
| 36 | 32 | merkle_root | internal (little) |
| 68 | 4 | ntime | little |
| 72 | 4 | nbits | little |
| 76 | 4 | nonce | little |

SHA-256 consumes 64-byte blocks. An 80-byte header therefore needs two blocks,
and the second one is mostly padding. The nonce lives in that second block:

```
block 1: header[0..63]     version + prevhash + first 28 bytes of merkle
block 2: header[64..79]    merkle tail + ntime + nbits + NONCE, then padding
block 3: the 32-byte first digest, then padding      <- the second SHA-256
```

Block 1 does not depend on the nonce. Hashing it once and resuming from the
resulting state is the **midstate** optimisation:

```
naive:     C1 + C2 + C3   per nonce      (3 compressions)
midstate:  C1 once, then C2 + C3         (2 compressions)  -> ~1.5x
```

`midstate()` stores the eight state words as native little-endian dwords — not
as a printable digest. That is exactly the layout `sha256d_tail` expects when it
resumes.

---

## The hot loop

```c
for (;;) {
    if (shared.epoch != my_epoch)      /* new job / difficulty / extranonce1 */
        reload everything, restart the scan;

    if (!have_prefix)                  /* once per extranonce2 */
        build coinbase -> merkle -> header -> midstate + tail;

    for (65536 hashes) {
        patch nonce into tail[12..15];
        hash = engine(midstate, tail);
        update best;
        if (hash <= share_target)   submit;
        if (hash <= network_target) report block;
        nonce++;
        if (nonce wrapped) { extranonce2 += nthreads; rebuild prefix; }
    }
    publish counters; merge best;
}
```

**Search space partitioning.** Worker `t` takes `extranonce2 = t, t+N, t+2N, …`
and scans the entire 32-bit nonce range for each. No coordination, no overlap.

**The epoch mechanism.** Main bumps `Shared.epoch` on every notify, difficulty
change or subscribe reply. Workers compare it with their local copy at batch
boundaries. This is how a new block on the network reaches all workers within
one batch — milliseconds — without any condition variables.

**Why batch 65536.** It amortises the mutex and the atomic counter over enough
work to be free, while keeping job-switch latency far below the pool's job
interval. In the AVX2 path the batch is 8192 calls × 8 lanes = the same 65536.

**Best-difficulty filter.** Building a full `u256` for every hash would be
wasteful, so the top limb is compared first; the full comparison only happens
when the hash could plausibly beat the record.

---

## Hashing engines

| Engine | Requires | Compressions per nonce | Hashes per call |
|---|---|---:|---:|
| `scalar` | any x86-64 | 2 | 1 |
| `shani` | SHA-NI + SSSE3 + SSE4.1 | 2 | 1 |
| `avx2` | AVX2 | 2 | 8 |

All three use the midstate. The engine is picked once at startup and stored in
a function pointer, so the hot loop pays an indirect call and nothing else.

### AVX2 multi-buffer

A single SHA-256 is a long serial dependency chain; execution ports sit partly
idle. Nonces are independent, so eight hashes are computed side by side, one per
32-bit lane of a YMM register:

```
          lane0   lane1   lane2   ...   lane7
W[3]  =   n+0     n+1     n+2     ...   n+7     <- the only word that differs
W[i]  =   broadcast constant for every i != 3
st[j] =   eight copies of state word j, evolving in parallel
result:   eight digests per pass
```

A convenient detail in phase 2: the first digest's bytes *are* the state words
in big-endian, so the second message is `W[i] = st[i]` with no shuffling at all.

### Why tuning runs at N threads

Because the winner changes with thread count. Measured on real hardware:

| CPU | Engine | 8 threads | 16 threads | 24 threads |
|---|---|---:|---:|---:|
| i7-10700F (no SHA-NI) | scalar | 11.0 | – | – |
| i7-10700F | avx2 | 70.4 | 91.4 | – |
| i9-12900KF | shani | 85.6 | 142.0 | 202.9 |
| i9-12900KF | avx2 | 102.2 | 136.6 | 169.6 |

(MH/s.) Three effects explain the crossovers:

1. **SHA-NI is latency-bound**, so SMT fills the stalls: roughly +66%.
2. **AVX2 already saturates the vector ports**, so SMT adds only ~34%.
3. **Hybrid E-cores** execute 256-bit operations in two passes but run SHA-NI
   natively, which flips the ranking again at full thread count.

A single-threaded microbenchmark would pick the wrong engine. The benchmark
therefore spawns exactly `-t N` threads and runs the same inner work as mining
(hash + best filter + target compare), not just the hash core.

---

## Targets, difficulty and byte order

A hash is treated as a 256-bit little-endian number, stored as four 64-bit limbs
(`l[0]` least significant). The raw digest bytes are already in that order.

```
DIFF1  = 0xffff * 2^208                  (the "difficulty 1" target)
target = DIFF1 / difficulty
```

Two different targets are in play:

| Target | Source | Meaning |
|---|---|---|
| share target | `mining.set_difficulty` | easy; proof of work for pool statistics |
| network target | `nbits` in the job | hard; a real block |

The network target is always stricter, so the block check runs only inside a
share hit — one comparison saved on every ordinary hash.

### Byte order rules (the classic source of bugs)

| Item | Rule |
|---|---|
| `version`, `nbits`, `ntime` from Stratum | big-endian hex → write little-endian into the header |
| `prevhash` from Stratum | bytes reversed **inside each 4-byte word**; undo per word, not globally |
| merkle branches | internal order, concatenate as-is |
| coinbase halves | raw bytes, no transformation |
| SHA-256 message words | big-endian; padding length is a big-endian 64-bit bit count |
| `nonce` in `mining.submit` | big-endian hex of the numeric value |
| `extranonce2` in `mining.submit` | hex of exactly the bytes that were inserted |
| digest for display | reversed byte order |

---

## Stratum conversation

```
miner                                     pool
  |  mining.subscribe   (id 1)              |
  | --------------------------------------> |
  |     [subscriptions, extranonce1, size]  |
  | <-------------------------------------- |
  |  mining.authorize   (id 2)              |
  | --------------------------------------> |
  |                             true/false  |
  | <-------------------------------------- |
  |                mining.set_difficulty    |
  | <-------------------------------------- |
  |                       mining.notify     |
  | <-------------------------------------- |
  |  mining.submit      (id 100, 101, ...)  |
  | --------------------------------------> |
  |                             true/false  |
  | <-------------------------------------- |
```

Reply ids: `1` subscribe, `2` authorize, `>= 100` a share verdict. Everything
else is a server notification matched by method name.

Messages are newline-delimited JSON. The receive buffer keeps a partial line
until the rest arrives; a 200 ms socket timeout lets the main loop wake up to
redraw the status even when the pool is silent.

---

## Concurrency rules

- `Shared` is read and written only under `g_state_mtx`. Workers copy the whole
  job by value once per epoch change, then work on their private copy.
- Fixed-size buffers inside `Job` mean **no allocation in the hot loop**.
- Counters are `_Atomic uint64_t`, accumulated locally and flushed once per
  batch rather than incremented per hash.
- `best` is kept per worker and merged under the mutex; the shared value only
  ever decreases (a smaller hash is a better one).
- The JSON parser uses a file-scope cursor and is called only from main.
- Every parsed tree is freed with `jfree()`; a long-running miner does not leak.

---

## Verification

`selftest()` runs before any mining and checks:

1. Two hardcoded known-answer SHA-256d digests, produced by an independent
   implementation, against the software path.
2. The midstate path against the same vectors.
3. The assembly path, if SHA-NI was selected.
4. The AVX2 path at three nonce bases, including `0xFFFFFFF8` — the last full
   group before the 32-bit nonce wraps — to catch lane arithmetic at the edge.

Comparing the fast paths only against our own software code would not be
enough: a shared bug would cancel out. The external vectors close that hole.
On mismatch the program exits instead of submitting invalid shares.

---

## Failure handling

| Event | Behaviour |
|---|---|
| connect fails | print, sleep 5 s, retry |
| pool closes socket | invalidate the job, reconnect |
| receive timeout | normal; redraw status and continue |
| new job / difficulty | bump epoch; workers restart their scan |
| share rejected | count it, print; usually a stale share |
| self-test mismatch | exit(2), never mine |

On reconnect the session is invalidated (`have_job = 0`, `extranonce1` cleared)
so workers idle until a fresh subscribe and notify arrive. Shares queued for
the old session are not resent — their job ids no longer exist.

---

## Where to start reading

1. `main()` — the startup sequence and the reconnect loop.
2. `worker()` — the hot loop; everything else exists to feed it.
3. `parse_job()` + `handle_line()` — how pool messages become state.
4. `midstate()` and `sha256d_tail_sw()` — the optimisation, in readable C.
5. `sha256d_tail_x8()` — the same thing eight lanes wide.
6. `sha256ni.S` — read the file header first; the register conventions and the
   implicit `XMM0` operand are explained there.

---

## Limitations and ideas

Known gaps, all deliberate for clarity:

- Stratum v1 only; no TLS, no version rolling (`mining.configure`), no
  `mining.set_extranonce`, no `ntime` rolling.
- The SHA-NI assembly uses a **two-pass** message schedule: it writes `W+K` to
  the stack and reads it back. A fused one-pass schedule (Linux kernel,
  RustCrypto) avoids 32 stack round-trips per block.
- The scalar SHA-256 is a textbook loop with a full `W[64]` array. A rolling
  16-word window and unrolled rounds would make it competitive with tuned
  libraries — and would let the midstate advantage show fully.
- The JSON parser is minimal and Stratum-shaped, not a general-purpose library.

Good exercises if you want to learn from this code:

1. Implement the fused SHA-NI schedule and measure the difference.
2. Add `ntime` rolling so a worker can refresh its own timestamp.
3. Optimise the scalar compression, then re-run `-e scalar` vs `-e avx2`.
4. On a hybrid CPU, try selecting the engine **per thread** (AVX2 on P-cores,
   SHA-NI on E-cores) and see whether it beats a single global choice.