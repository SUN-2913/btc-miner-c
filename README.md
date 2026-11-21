# btc-miner-c

A CPU Bitcoin **solo** miner written in C with hand-written x86-64 assembly.
Stratum v1 client, three hashing engines, automatic engine selection benchmarked
at your actual thread count.

**No built-in pool. No built-in payout address.** Both are required command-line
arguments. The miner never mines for anyone but you.

[Русская версия](README.ru.md)

---

## ⚠️ Read this first: it is a lottery, not an income source

Bitcoin network hashrate is on the order of 10²¹ H/s. A fast desktop CPU with all
optimisations in this project reaches roughly 10² MH/s — about **10⁻¹³ of the network**.

Practical consequences:

- **Finding a block**: expected time is measured in millions of years. It can
  theoretically happen on the first hash, but do not plan around it.
- **Finding a pool share**: solo.ckpool.org uses a minimum share difficulty of
  10,000. At ~90 MH/s that is one share every ~5 days; at ~200 MH/s, ~2.5 days.
  Until your first share is accepted, the pool's web statistics will show nothing.
- **Shares pay nothing on a solo pool.** They are feedback only. You are paid
  only if you find a whole block.
- **Electricity is not free.** Six AVX2 threads add roughly 60–80 W over idle.
  Run the numbers against your tariff before leaving it on 24/7.

This project exists to study CPU microarchitecture — SHA-NI, AVX2 multi-buffer,
SMT scaling, hybrid P/E cores — and to buy a very cheap lottery ticket.
Treat it that way.

---

## Features

- **Three hashing engines**, all using the midstate optimisation:
  - `shani` — hand-written x86-64 assembly using SHA-NI instructions
  - `avx2` — 8 nonces hashed in parallel in 8×32-bit AVX2 lanes (multi-buffer)
  - `scalar` — portable C fallback for any x86-64 CPU
- **Midstate**: the first 64 bytes of the header are hashed once per job/extranonce2,
  so the hot loop performs 2 SHA-256 compressions per nonce instead of 3.
- **Auto-tuning at your thread count**: at startup every available engine is
  benchmarked using exactly `-t N` threads, and the fastest wins. This matters:
  the winner changes with thread count (see benchmarks below).
- **Self-test against known-answer vectors** before any mining starts. If the
  hashing engine is wrong, the program exits instead of submitting garbage.
- **Single-line live status** — no console spam. Only meaningful events print
  above the status line.
- **Best difficulty tracking** — see your progress even when no share is found.
- **Block detection** — decodes `nbits` into the network target; on a hit prints
  a banner and dumps everything to `BLOCK_FOUND.txt`.
- **Startup delay** (`-d`) for autostart: wait for the OS to settle before
  benchmarking, so the tuning is not skewed by boot-time load. CPU stays idle.
- **Thread limiting** (`-t`) so the machine remains usable.
- Full Stratum v1: subscribe, authorize, notify, set_difficulty, submit,
  vardiff, clean jobs, automatic reconnect.
- No telemetry, no auto-update, no wallet access, no private keys. It only
  connects to the pool you specify.

---

## Requirements

- x86-64 CPU (any). SHA-NI and AVX2 are detected at runtime, not required.
- GCC with SHA-NI-capable binutils.
  - Windows: MSYS2 **UCRT64** / MinGW-w64 (`pacman -S mingw-w64-ucrt-x86_64-gcc make`)
  - Linux: `gcc`, `make`, `libpthread`
- MSVC is **not** supported (GNU assembler syntax and `unsigned __int128`).
- A Bitcoin address and a Stratum pool endpoint.

## Architecture

New to the code? Read [ARCHITECTURE.md](ARCHITECTURE.md) — thread model, data
flow from Stratum JSON to a hash, the midstate trick, and why engine selection
is benchmarked at your thread count.

## Build

```bash
# Windows (MSYS2 UCRT64 shell)
gcc -O3 -msha -msse4.1 -o btc-miner-c.exe src/miner.c src/sha256ni.S -lws2_32 -lm

# Linux
gcc -O3 -msha -msse4.1 -o btc-miner-c src/miner.c src/sha256ni.S -lpthread -lm

# or simply
make
```

AVX2 code is compiled through a local `#pragma GCC target("avx2")`, so no global
`-mavx2` is needed and the binary still runs on older CPUs.

## Usage

```
REQUIRED
  -a ADDR        Bitcoin payout address (no default)
  -p HOST:PORT   Stratum pool endpoint (no default)

OPTIONAL
  -w NAME        Worker suffix appended to the address (default: cpu1)
  -t N           Mining threads (default: all logical CPUs)
  -x PASS        Pool password (default: x)
  -e ENGINE      auto | shani | avx2 | scalar (default: auto)
  -d MIN         Startup delay in minutes, fractional allowed (default: 0)
  -h             Show help
```

The Stratum username is built as `ADDRESS.WORKER`. The payout goes to `ADDRESS`;
the worker suffix is only a label for pool statistics.

### Examples

```bash
# minimal
btc-miner-c -a bc1qyouraddress... -p solo.ckpool.org:3333

# leave the machine usable: 6 threads
btc-miner-c -a bc1qyouraddress... -p solo.ckpool.org:3333 -t 6

# autostart: wait 5 minutes after boot, then tune and mine
btc-miner-c -a bc1qyouraddress... -p solo.ckpool.org:3333 -t 6 -d 5 -w desk

# force an engine (skips tuning) - useful for benchmarking
btc-miner-c -a bc1qyouraddress... -p solo.ckpool.org:3333 -t 8 -e avx2
btc-miner-c -a bc1qyouraddress... -p solo.ckpool.org:3333 -t 8 -e scalar
```

### Several machines

Use the same address with **different worker suffixes** so you can tell them
apart in pool statistics. Identical suffixes are allowed — the pool sums the
hashrate and does not disconnect duplicates — but then you cannot see which
machine went down.

```bash
btc-miner-c -a bc1qyouraddress... -p solo.ckpool.org:3333 -t 6  -w i7
btc-miner-c -a bc1qyouraddress... -p solo.ckpool.org:3333 -t 10 -w i9
```

### Autostart on Windows

`Win+R` → `shell:startup` → create a shortcut:

```
Target:    "C:\path\to\btc-miner-c.exe" -a bc1qyouraddress... -p solo.ckpool.org:3333 -t 6 -d 5 -w desk
Start in:  C:\path\to
Run:       Minimized
```

Set "Start in" explicitly — `BLOCK_FOUND.txt` is written to the working directory.

---

## Output

```
[cpu] Intel(R) Core(TM) i7-10700F CPU @ 2.90GHz
[cpu] SHA-NI: no | AVX2: yes | threads: 6
[tune] benchmarking on 6 thread(s), 0.35 s per engine...
[tune] scalar :     8.24 MH/s
[tune] avx2 x8:    52.71 MH/s
[tune] selected: avx2 x8 (52.71 MH/s)
[cpu] engine: AVX2 x8 multi-buffer + midstate
[selftest] OK (reference vectors, x8 lanes)
[net] connected
[pool] authorized
[00:02:15] 52.70 MH/s   | 7.11G     hashes | A/R 0/0 | diff 10000 | best 1.65 | job 6aff9dca
```

The last line updates in place. Fields:

| Field | Meaning |
|---|---|
| `[hh:mm:ss]` | uptime |
| `MH/s` | smoothed hashrate |
| `hashes` | total double-SHA256 hashes computed |
| `A/R` | shares accepted / rejected by the pool |
| `diff` | current share difficulty assigned by the pool |
| `best` | highest difficulty of any hash found so far |
| `job` | current pool job id (truncated) |

`best` grows roughly as `total_hashes / 2³²`. When it reaches `diff`, a share is
submitted. A rejected share is usually "stale" (the pool changed jobs while your
share was in flight) — a few percent is normal.

---

## Benchmarks

Measured with this code, real runs, `-e` forcing each engine:

| CPU | Engine | Threads | MH/s |
|---|---|---:|---:|
| i7-10700F (no SHA-NI) | scalar | 8 | 11.0 |
| i7-10700F | avx2 x8 | 8 | 70.4 |
| i7-10700F | avx2 x8 | 16 | 91.4 |
| i9-12900KF | shani | 8 | 85.6 |
| i9-12900KF | avx2 x8 | 8 | 102.2 |
| i9-12900KF | shani | 16 | 142.0 |
| i9-12900KF | avx2 x8 | 16 | 136.6 |
| i9-12900KF | shani | 24 | 202.9 |
| i9-12900KF | avx2 x8 | 24 | 169.6 |

Things worth noticing:

1. **Multi-buffer is the big lever when SHA-NI is absent**: 6.4× over scalar on
   the i7. For reference, a comparable Rust implementation using the `sha2`
   crate produced 9.8 MH/s on the same i7 at 8 threads.
2. **A hardware instruction does not automatically win.** On a dedicated P-core
   the AVX2 path beats the SHA-NI assembly, because the assembly is
   latency-bound on a single hash while AVX2 hides latency behind 8 lanes.
3. **SMT changes the winner.** SHA-NI gains ~66% from SMT (latency-bound),
   AVX2 only ~34% (ports already saturated). Hence the crossover at 16 threads.
4. **Hybrid cores decide it.** Gracemont E-cores execute 256-bit ops in two
   passes but run SHA-NI natively, so at the full 24 threads SHA-NI wins.

This is exactly why auto-tuning benchmarks at your `-t` value instead of using
a fixed priority list.

---

## Safety, privacy, legality

- The miner has **no hardcoded pool and no hardcoded payout address**. Both are
  mandatory arguments. The address in the help footer and in this README is a
  donation address only and is never used as a default.
- No private keys, no wallet files, no telemetry, no network calls other than
  to the pool endpoint you pass.
- Run it only on hardware you own or are authorised to use.
- Check your local regulations regarding cryptocurrency mining and your
  electricity tariff.
- Do not use CI infrastructure (GitHub Actions and similar) to run the miner.

## Project layout

```
src/miner.c      Stratum client, threading, engine selection, UI
src/sha256ni.S   SHA-256d in x86-64 assembly (SHA-NI), Windows + SysV ABI
Makefile         build for Linux and MinGW-w64
ARCHITECTURE.md     how the pieces fit together, and why (English)
```

## Known limitations

- Stratum v1 only; no TLS, no version rolling (`mining.configure`), no
  `mining.set_extranonce` (NiceHash-style), no `ntime` rolling.
- The SHA-NI assembly uses a two-pass message schedule; a fused one-pass
  schedule would be faster. Contributions welcome.
- The JSON parser is minimal and tailored to Stratum messages.

## License

MIT — see [LICENSE](LICENSE).

---

## Donations

If this project taught you something about CPUs and you feel like it:

**BTC:** `bc1q563zveamrcj3mu5gjlcpcv8ythuhjha9ychr6r`

No pressure. And honestly — you will probably get more value from reading the
assembly than from running the miner. 🙂