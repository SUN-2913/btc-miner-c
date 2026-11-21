/* ============================================================================
 * btc-miner-c 3.0 - CPU Bitcoin solo miner (Stratum v1)
 * ----------------------------------------------------------------------------
 * WHAT THIS IS
 *   A study project: a working solo miner that talks to a real pool, with
 *   three interchangeable SHA-256d engines and a runtime benchmark that picks
 *   the fastest one for the exact thread count you asked for.
 *   It is a lottery ticket, not an income source. See README.
 *
 * WHAT THIS IS NOT
 *   No built-in pool, no built-in payout address (both are required flags),
 *   no wallet access, no private keys, no telemetry, no auto-update.
 *   The only network peer is the pool endpoint passed via -p.
 *
 * ----------------------------------------------------------------------------
 * THREAD MODEL
 * ----------------------------------------------------------------------------
 *   main thread     owns the socket for READING, parses pool messages,
 *                   updates shared state, and is the ONLY thread that prints.
 *   N mining workers hash nonces. They never print; they push text events
 *                   into a queue that main drains. They send shares directly
 *                   to the socket under g_send_mtx (full duplex is fine).
 *   benchmark threads  short-lived, only during startup tuning.
 *
 *   Why a single printer: the status line is redrawn in place with '\r'.
 *   If two threads printed concurrently the line would be shredded.
 *
 * ----------------------------------------------------------------------------
 * DATA FLOW (one mining job)
 * ----------------------------------------------------------------------------
 *   pool JSON  --mining.notify-->  Job { prevhash, coinb1, coinb2, merkle
 *                                        branches, version, nbits, ntime }
 *   per extranonce2:
 *       coinbase = coinb1 || extranonce1 || extranonce2 || coinb2
 *       merkle   = fold(sha256d(coinbase), branches)
 *       header   = version || prevhash || merkle || ntime || nbits || nonce
 *       midstate = SHA256 state after absorbing header[0..63]   <-- once
 *   per nonce:
 *       tail = header[64..79] with the nonce patched in
 *       hash = sha256d_tail(midstate, tail)                     <-- hot loop
 *       hash <= share target   -> mining.submit
 *       hash <= network target -> BLOCK FOUND
 *
 * ----------------------------------------------------------------------------
 * MODULE MAP (search for the banners)
 * ----------------------------------------------------------------------------
 *   1. Platform abstraction   Win32 vs POSIX: threads, mutexes, time, sockets
 *   2. Network                connect / send-all / recv with timeout
 *   3. u256 and targets       256-bit compare, difficulty <-> target, nbits
 *   4. Software SHA-256       reference implementation + portable fallback
 *   5. Midstate helpers       the optimisation that removes 1 of 3 compressions
 *   6. AVX2 multi-buffer      8 nonces hashed in parallel, 8 x 32-bit lanes
 *   7. CPU detection          CPUID leaves/bits, engine function pointers
 *   8. Hex helpers
 *   9. JSON parser            minimal recursive descent, Stratum-shaped
 *  10. Job / shared state     what a job holds, the epoch mechanism, mutexes
 *  11. Event queue            workers -> main, single-printer discipline
 *  12. Console UI             one live line, events above it
 *  13. Stratum handlers       subscribe / authorize / notify / difficulty
 *  14. Mining worker          the hot loop, share and block detection
 *  15. Thread spawn helpers
 *  16. Engine benchmark       tuning at N threads, not single-threaded
 *  17. Self-test              known-answer vectors, refuse to mine if wrong
 *  18. CLI and main           required flags, delay, tuning, reconnect loop
 *
 * SPDX-License-Identifier: MIT
 * ==========================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <math.h>
#include <time.h>
#include <cpuid.h>
#include <immintrin.h>

#define TUNE_SEC 0.35   /* benchmark duration per engine, seconds */
#define VERSION  "3.0"

/* Implemented in sha256ni.S. Only called when CPUID reports SHA-NI. */
void sha256d_80(const unsigned char*, unsigned char*);
void sha256d_tail(const unsigned char*, const unsigned char*, unsigned char*);

/* ============================================================================
 * 1. PLATFORM ABSTRACTION
 * ----------------------------------------------------------------------------
 * Everything below this block is platform-independent. The differences are
 * confined to: thread handles, mutex type, sleeping, monotonic clock, CPU
 * count, and the socket API (Winsock needs WSAStartup and closesocket).
 * ==========================================================================*/
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  typedef SOCKET sock_t; typedef HANDLE thr_t; typedef CRITICAL_SECTION mtx_t;
  static void mtx_init(mtx_t*m){ InitializeCriticalSection(m); }
  static void mtx_lock(mtx_t*m){ EnterCriticalSection(m); }
  static void mtx_unlock(mtx_t*m){ LeaveCriticalSection(m); }
  static void sleep_ms(int ms){ Sleep(ms); }
  /* QueryPerformanceCounter is monotonic and sub-microsecond; time() is not
   * precise enough to measure a 0.35 s benchmark. */
  static double now_sec(void){ LARGE_INTEGER f,c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c); return (double)c.QuadPart/(double)f.QuadPart; }
  static int cpu_count(void){ SYSTEM_INFO si; GetSystemInfo(&si); return (int)si.dwNumberOfProcessors; }
  static void net_init(void){ WSADATA w; WSAStartup(MAKEWORD(2,2),&w); }
  static void net_close(sock_t s){ closesocket(s); }
  static int  net_recv(sock_t s,char*b,int n){ return recv(s,b,n,0); }
  static int  recv_timeout_ok(void){ int e=WSAGetLastError(); return e==WSAETIMEDOUT||e==WSAEWOULDBLOCK; }
#else
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <pthread.h>
  #include <errno.h>
  typedef int sock_t; typedef pthread_t thr_t; typedef pthread_mutex_t mtx_t;
  static void mtx_init(mtx_t*m){ pthread_mutex_init(m,NULL); }
  static void mtx_lock(mtx_t*m){ pthread_mutex_lock(m); }
  static void mtx_unlock(mtx_t*m){ pthread_mutex_unlock(m); }
  static void sleep_ms(int ms){ usleep(ms*1000); }
  static double now_sec(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec*1e-9; }
  static int cpu_count(void){ return (int)sysconf(_SC_NPROCESSORS_ONLN); }
  static void net_init(void){}
  static void net_close(sock_t s){ close(s); }
  static int  net_recv(sock_t s,char*b,int n){ return (int)recv(s,b,n,0); }
  static int  recv_timeout_ok(void){ return errno==EAGAIN||errno==EWOULDBLOCK; }
#endif

/* ============================================================================
 * 2. NETWORK
 * ----------------------------------------------------------------------------
 * Stratum v1 is line-delimited JSON over plain TCP. We use blocking sockets
 * with a 200 ms receive timeout: that lets the main loop wake up regularly to
 * redraw the status line and drain worker events without a second thread.
 * ==========================================================================*/
static sock_t net_connect(const char*host,const char*port){
    struct addrinfo h,*r,*a; memset(&h,0,sizeof h); h.ai_family=AF_UNSPEC; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,port,&h,&r)) return (sock_t)-1;
    sock_t s=(sock_t)-1;
    /* Try every address the resolver returned (IPv6 first, then IPv4, ...). */
    for(a=r;a;a=a->ai_next){
        s=socket(a->ai_family,a->ai_socktype,a->ai_protocol);
#ifdef _WIN32
        if(s==INVALID_SOCKET) continue;
#else
        if(s<0) continue;
#endif
        if(connect(s,a->ai_addr,(int)a->ai_addrlen)==0) break;
        net_close(s); s=(sock_t)-1;
    }
    freeaddrinfo(r);
#ifdef _WIN32
    if(s!=(sock_t)-1){ DWORD t=200; setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(const char*)&t,sizeof t); }
#else
    if(s>=0){ struct timeval t={0,200000}; setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof t); }
#endif
    return s;
}
/* send() may write fewer bytes than requested; loop until everything is out. */
static int net_send_all(sock_t s,const char*b,int n){
    int off=0; while(off<n){ int k=send(s,b+off,n-off,0); if(k<=0) return 0; off+=k; } return 1;
}

/* ============================================================================
 * 3. u256 AND TARGETS
 * ----------------------------------------------------------------------------
 * A hash is compared against a 256-bit target. We store it as four 64-bit
 * limbs in LITTLE-endian order: l[0] is the least significant word, l[3] the
 * most significant. The raw digest bytes are already in that order, so
 * memcpy of 8 bytes at offset i*8 gives limb i directly.
 *
 * Difficulty is defined relative to "difficulty 1":
 *     DIFF1 = 0xffff * 2^208
 *     target = DIFF1 / difficulty
 * Only the top limb of DIFF1 is non-zero (0xffff0000), which keeps the
 * division trivial.
 * ==========================================================================*/
typedef struct { uint64_t l[4]; } u256;

/* a < b as 256-bit unsigned numbers. Compare from the most significant limb. */
static int less256(const u256*a,const u256*b){ for(int i=3;i>=0;i--) if(a->l[i]!=b->l[i]) return a->l[i]<b->l[i]; return 0; }

/* hash <= target. Early-exits on the top limb, which is why this is cheap
 * enough to run on every single hash. */
static int meets(const unsigned char h[32],const u256*t){
    for(int i=3;i>=0;i--){ uint64_t v; memcpy(&v,h+i*8,8); if(v!=t->l[i]) return v<t->l[i]; } return 1;
}

/* target = floor(DIFF1 / difficulty), exactly.
 * Floating point alone would lose precision, so we scale by 1e9 and do a
 * 256-bit / 64-bit long division with 128-bit intermediates. */
static u256 target_from_diff(double d){
    const uint64_t S=1000000000ULL; uint64_t dv=(uint64_t)(d*(double)S); if(!dv)dv=1;
    uint64_t a[4]={0,0,0,0xffff0000ULL*S}; u256 o; unsigned __int128 rem=0;
    for(int i=3;i>=0;i--){ unsigned __int128 c=(rem<<64)|a[i]; o.l[i]=(uint64_t)(c/dv); rem=c%dv; } return o;
}

/* Decode the "compact bits" field of the block header into a full target.
 * Format: top byte = exponent, low 3 bytes = mantissa.
 *     value = mantissa * 256^(exponent-3)
 * This is the NETWORK target - used to recognise a real block, as opposed to
 * the much easier pool share target. */
static u256 target_from_nbits(uint32_t nb){
    unsigned e=nb>>24; uint64_t m=nb&0xffffff; u256 t={{0,0,0,0}};
    if(!m) return t;
    if(e<=3){ t.l[0]=m>>(8*(3-e)); }
    else{ unsigned bp=(e-3)*8, limb=bp/64, off=bp%64;
        if(limb<4){ t.l[limb]|=m<<off; if(off&&limb+1<4) t.l[limb+1]|=m>>(64-off); } }
    return t;
}

/* Inverse of the above, for display only: how "hard" was our best hash.
 * f64 has plenty of range for a human-readable number. */
static double hash_diff(const u256*h){
    for(int k=3;k>=0;k--) if(h->l[k]){ double m=(double)h->l[k]; if(k>0)m+=(double)h->l[k-1]/18446744073709551616.0; return 65535.0*pow(2.0,208-64*k)/m; }
    return INFINITY;
}
static void fmt_diff(double d,char*b){ if(d>=1e12)sprintf(b,"%.2fT",d/1e12); else if(d>=1e9)sprintf(b,"%.2fG",d/1e9); else if(d>=1e6)sprintf(b,"%.2fM",d/1e6); else if(d>=1e3)sprintf(b,"%.2fk",d/1e3); else sprintf(b,"%.2f",d); }
static void fmt_speed(double s,char*b){ if(s>=1e6)sprintf(b,"%.2f MH/s",s/1e6); else if(s>=1e3)sprintf(b,"%.2f kH/s",s/1e3); else sprintf(b,"%.0f H/s",s); }
static void fmt_count(uint64_t n,char*b){ double x=(double)n; if(x>=1e12)sprintf(b,"%.2fT",x/1e12); else if(x>=1e9)sprintf(b,"%.2fG",x/1e9); else if(x>=1e6)sprintf(b,"%.2fM",x/1e6); else if(x>=1e3)sprintf(b,"%.2fk",x/1e3); else sprintf(b,"%llu",(unsigned long long)n); }

/* ============================================================================
 * 4. SOFTWARE SHA-256
 * ----------------------------------------------------------------------------
 * Two jobs:
 *   a) Reference implementation. The self-test compares the assembly and the
 *      AVX2 path against this code AND against hardcoded known-answer digests,
 *      so a bug in the fast paths cannot slip through.
 *   b) Portable fallback engine for CPUs without SHA-NI or AVX2.
 *
 * It is also used for coinbase / merkle work, which happens once per job or
 * per extranonce2 (i.e. once per ~4 billion hashes) - speed there is irrelevant.
 *
 * This is a textbook implementation: full W[64] array, then 64 rounds.
 * A tuned implementation would use a rolling 16-word window and unrolled
 * rounds; that is why the scalar engine is slower per compression than, say,
 * the RustCrypto sha2 backend.
 * ==========================================================================*/
static const uint32_t IVw[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))   /* rotate right, 32-bit */

/* The compression function: absorbs one 64-byte block into state h[8]. */
static void sha256_compress(uint32_t h[8],const uint8_t b[64]){
    uint32_t w[64];
    /* Message words are big-endian in memory. */
    for(int i=0;i<16;i++) w[i]=((uint32_t)b[4*i]<<24)|((uint32_t)b[4*i+1]<<16)|((uint32_t)b[4*i+2]<<8)|b[4*i+3];
    /* Message schedule: W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16]. */
    for(int i=16;i<64;i++){ uint32_t s0=RR(w[i-15],7)^RR(w[i-15],18)^(w[i-15]>>3); uint32_t s1=RR(w[i-2],17)^RR(w[i-2],19)^(w[i-2]>>10); w[i]=w[i-16]+s0+w[i-7]+s1; }
    uint32_t a=h[0],bb=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<64;i++){
        uint32_t S1=RR(e,6)^RR(e,11)^RR(e,25),ch=(e&f)^((~e)&g),t1=hh+S1+ch+K[i]+w[i];
        uint32_t S0=RR(a,2)^RR(a,13)^RR(a,22),mj=(a&bb)^(a&c)^(bb&c),t2=S0+mj;
        hh=g;g=f;f=e;e=d+t1;d=c;c=bb;bb=a;a=t1+t2;
    }
    /* Feed-forward (Merkle-Damgard). */
    h[0]+=a;h[1]+=bb;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

/* Full SHA-256 of an arbitrary-length message, with padding.
 * Padding: 0x80, then zeros, then the 64-bit big-endian bit length, so that
 * the total is a multiple of 64. If the length does not fit in the current
 * block, a second block is needed - hence the 128-byte buffer. */
static void sha256(const uint8_t*m,size_t len,uint8_t out[32]){
    uint32_t h[8]; memcpy(h,IVw,sizeof h);
    size_t full=len/64;
    for(size_t i=0;i<full;i++) sha256_compress(h,m+64*i);
    uint8_t b[128]; memset(b,0,128); size_t rem=len%64; memcpy(b,m+64*full,rem); b[rem]=0x80;
    size_t pl=(rem<56)?64:128; uint64_t bits=(uint64_t)len*8;
    for(int i=0;i<8;i++) b[pl-1-i]=(uint8_t)(bits>>(8*i));
    sha256_compress(h,b); if(pl==128) sha256_compress(h,b+64);
    for(int i=0;i<8;i++){ out[4*i]=(uint8_t)(h[i]>>24); out[4*i+1]=(uint8_t)(h[i]>>16); out[4*i+2]=(uint8_t)(h[i]>>8); out[4*i+3]=(uint8_t)h[i]; }
}
/* Bitcoin hashes everything twice. */
static void sha256d(const uint8_t*m,size_t n,uint8_t out[32]){ uint8_t t[32]; sha256(m,n,t); sha256(t,32,out); }

/* ============================================================================
 * 5. MIDSTATE HELPERS
 * ----------------------------------------------------------------------------
 * midstate() = the SHA-256 state after absorbing exactly one 64-byte block,
 * with NO padding and NO final byte swap. It is stored as native little-endian
 * dwords, which is the layout sha256d_tail / sha256d_tail_x8 expect.
 *
 * sha256d_tail_sw() = software twin of the assembly sha256d_tail:
 *     resume from midstate -> absorb tail16 + padding + 640-bit length
 *     -> that is the first digest -> hash it again.
 * Two compressions per nonce instead of three.
 * ==========================================================================*/
static void midstate(const uint8_t blk64[64],uint8_t out32[32]){
    uint32_t h[8]; memcpy(h,IVw,sizeof h);
    sha256_compress(h,blk64);
    for(int i=0;i<8;i++){ out32[4*i]=(uint8_t)h[i]; out32[4*i+1]=(uint8_t)(h[i]>>8); out32[4*i+2]=(uint8_t)(h[i]>>16); out32[4*i+3]=(uint8_t)(h[i]>>24); }
}
static void sha256d_tail_sw(const uint8_t mid[32],const uint8_t tail[16],uint8_t out[32]){
    uint32_t h[8];
    for(int i=0;i<8;i++)
        h[i]=(uint32_t)mid[4*i]|((uint32_t)mid[4*i+1]<<8)|((uint32_t)mid[4*i+2]<<16)|((uint32_t)mid[4*i+3]<<24);
    uint8_t b[64]; memset(b,0,64); memcpy(b,tail,16); b[16]=0x80;
    uint64_t bits=640; for(int i=0;i<8;i++) b[63-i]=(uint8_t)(bits>>(8*i));  /* 80 bytes * 8 */
    sha256_compress(h,b);
    uint8_t first[32];
    for(int i=0;i<8;i++){ first[4*i]=(uint8_t)(h[i]>>24); first[4*i+1]=(uint8_t)(h[i]>>16); first[4*i+2]=(uint8_t)(h[i]>>8); first[4*i+3]=(uint8_t)h[i]; }
    sha256(first,32,out);
}

/* ============================================================================
 * 6. AVX2 MULTI-BUFFER (8 nonces at once)
 * ----------------------------------------------------------------------------
 * IDEA
 *   A single SHA-256 is a long serial dependency chain: each round waits for
 *   the previous one, so the execution ports sit partly idle. Nonces are
 *   independent, so instead of one hash we compute EIGHT in parallel, one per
 *   32-bit lane of a 256-bit YMM register. Same instruction count, 8 results.
 *   This is the classic cpuminer trick for CPUs without SHA-NI.
 *
 * LAYOUT
 *   st[0..7]  : the eight state words A..H, each a vector of 8 lanes
 *   W[0..63]  : message schedule, each word a vector of 8 lanes
 *   Only W[3] differs between lanes - it carries the nonce. Everything else
 *   is broadcast with _mm256_set1_epi32.
 *
 * TWO PHASES
 *   phase 1: block = tail16 (with per-lane nonce) + padding + 640-bit length,
 *            starting from the midstate  -> first digest, still in lanes
 *   phase 2: message = that 32-byte digest. Convenient detail: the digest
 *            bytes ARE the state words in big-endian, so W[i] = st[i] with
 *            no shuffling at all. Fresh IV, then compress.
 *
 * The pragma scopes AVX2 to this region only, so the rest of the file stays
 * runnable on older CPUs and no global -mavx2 is needed.
 * ==========================================================================*/
#pragma GCC push_options
#pragma GCC target("avx2")
#define ROR32(x,n) _mm256_or_si256(_mm256_srli_epi32((x),(n)),_mm256_slli_epi32((x),32-(n)))
#define BSIG0(x) _mm256_xor_si256(_mm256_xor_si256(ROR32(x,2),ROR32(x,13)),ROR32(x,22))   /* big sigma0 */
#define BSIG1(x) _mm256_xor_si256(_mm256_xor_si256(ROR32(x,6),ROR32(x,11)),ROR32(x,25))   /* big sigma1 */
#define SSIG0(x) _mm256_xor_si256(_mm256_xor_si256(ROR32(x,7),ROR32(x,18)),_mm256_srli_epi32((x),3))   /* small sigma0 */
#define SSIG1(x) _mm256_xor_si256(_mm256_xor_si256(ROR32(x,17),ROR32(x,19)),_mm256_srli_epi32((x),10)) /* small sigma1 */
/* Ch(e,f,g) = g ^ (e & (f^g))  - equivalent to (e&f)^(~e&g), fewer ops. */
#define CHV(e,f,g) _mm256_xor_si256((g),_mm256_and_si256((e),_mm256_xor_si256((f),(g))))
/* Maj(a,b,c) = (a&b) ^ (c & (a^b)) */
#define MAJV(a,b,c) _mm256_xor_si256(_mm256_and_si256((a),(b)),_mm256_and_si256((c),_mm256_xor_si256((a),(b))))

/* Expand W[0..15] into W[16..63], eight lanes at a time. */
static void sched_x8(__m256i W[64]){
    for(int t=16;t<64;t++)
        W[t]=_mm256_add_epi32(_mm256_add_epi32(SSIG1(W[t-2]),W[t-7]),
                              _mm256_add_epi32(SSIG0(W[t-15]),W[t-16]));
}
/* 64 rounds on eight independent hashes. */
static void comp_x8(__m256i st[8],const __m256i W[64]){
    __m256i a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
    for(int t=0;t<64;t++){
        __m256i kv=_mm256_set1_epi32((int)K[t]);
        __m256i t1=_mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(h,BSIG1(e)),CHV(e,f,g)),
                                    _mm256_add_epi32(kv,W[t]));
        __m256i t2=_mm256_add_epi32(BSIG0(a),MAJV(a,b,c));
        h=g;g=f;f=e;e=_mm256_add_epi32(d,t1);d=c;c=b;b=a;a=_mm256_add_epi32(t1,t2);
    }
    st[0]=_mm256_add_epi32(st[0],a); st[1]=_mm256_add_epi32(st[1],b);
    st[2]=_mm256_add_epi32(st[2],c); st[3]=_mm256_add_epi32(st[3],d);
    st[4]=_mm256_add_epi32(st[4],e); st[5]=_mm256_add_epi32(st[5],f);
    st[6]=_mm256_add_epi32(st[6],g); st[7]=_mm256_add_epi32(st[7],h);
}
/* out[l] is the digest for nonce_base + l, l = 0..7. */
static void sha256d_tail_x8(const uint8_t mid[32],const uint8_t tail[16],
                            uint32_t nonce_base,uint8_t out[8][32]){
    __m256i W[64],st[8];
    uint32_t mw[8];
    for(int i=0;i<8;i++)
        mw[i]=(uint32_t)mid[4*i]|((uint32_t)mid[4*i+1]<<8)|((uint32_t)mid[4*i+2]<<16)|((uint32_t)mid[4*i+3]<<24);
    for(int i=0;i<8;i++) st[i]=_mm256_set1_epi32((int)mw[i]);

    /* tail[0..11] is constant across lanes; tail[12..15] is the nonce and is
     * replaced below. Message words are big-endian, hence the shifts. */
    uint32_t w0=((uint32_t)tail[0]<<24)|((uint32_t)tail[1]<<16)|((uint32_t)tail[2]<<8)|tail[3];
    uint32_t w1=((uint32_t)tail[4]<<24)|((uint32_t)tail[5]<<16)|((uint32_t)tail[6]<<8)|tail[7];
    uint32_t w2=((uint32_t)tail[8]<<24)|((uint32_t)tail[9]<<16)|((uint32_t)tail[10]<<8)|tail[11];
    /* The header stores the nonce little-endian, but W[3] must read it as a
     * big-endian word - so byte-swap each lane's nonce. */
    uint32_t nb[8]; for(int l=0;l<8;l++) nb[l]=__builtin_bswap32(nonce_base+(uint32_t)l);
    W[0]=_mm256_set1_epi32((int)w0);
    W[1]=_mm256_set1_epi32((int)w1);
    W[2]=_mm256_set1_epi32((int)w2);
    W[3]=_mm256_loadu_si256((const __m256i*)nb);
    W[4]=_mm256_set1_epi32((int)0x80000000u);   /* 0x80 terminator after 16 bytes */
    for(int i=5;i<14;i++) W[i]=_mm256_setzero_si256();
    W[14]=_mm256_setzero_si256();
    W[15]=_mm256_set1_epi32(640);               /* 80-byte message, in bits */
    sched_x8(W); comp_x8(st,W);

    /* Phase 2: the first digest becomes the message. Its bytes are exactly
     * the state words in big-endian, so no conversion is needed. */
    for(int i=0;i<8;i++) W[i]=st[i];
    W[8]=_mm256_set1_epi32((int)0x80000000u);   /* 32 bytes of data, then 0x80 */
    for(int i=9;i<14;i++) W[i]=_mm256_setzero_si256();
    W[14]=_mm256_setzero_si256();
    W[15]=_mm256_set1_epi32(256);               /* 32-byte message, in bits */
    for(int i=0;i<8;i++) st[i]=_mm256_set1_epi32((int)IVw[i]);
    sched_x8(W); comp_x8(st,W);

    /* Scatter lanes back into eight ordinary 32-byte digests. */
    uint32_t tmp[8];
    for(int i=0;i<8;i++){
        _mm256_storeu_si256((__m256i*)tmp,st[i]);
        for(int l=0;l<8;l++){
            uint32_t v=tmp[l];
            out[l][4*i]=(uint8_t)(v>>24); out[l][4*i+1]=(uint8_t)(v>>16);
            out[l][4*i+2]=(uint8_t)(v>>8); out[l][4*i+3]=(uint8_t)v;
        }
    }
}
#pragma GCC pop_options

/* ============================================================================
 * 7. CPU DETECTION AND ENGINE POINTERS
 * ----------------------------------------------------------------------------
 * SHA-NI: CPUID leaf 7 subleaf 0, EBX bit 29. We also require SSSE3 and SSE4.1
 * because the assembly uses pshufb / palignr / pblendw.
 * AVX2: __builtin_cpu_supports() is used instead of raw CPUID because it also
 * verifies that the OS enables the YMM state (XGETBV) - a CPU can have AVX2
 * while the OS does not save the registers.
 *
 * The engine is chosen ONCE at startup and stored in a function pointer, so
 * the hot loop pays only an indirect call, with no per-hash branching.
 * ==========================================================================*/
static int cpu_has_sha(void){
    unsigned a,b,c,d;
    if(!__get_cpuid(1,&a,&b,&c,&d)) return 0;
    if(!((c>>9)&1))  return 0;   /* SSSE3  */
    if(!((c>>19)&1)) return 0;   /* SSE4.1 */
    if(!__get_cpuid_count(7,0,&a,&b,&c,&d)) return 0;
    return (b>>29)&1;            /* SHA extensions */
}
static void cpu_brand(char out[64]){
    unsigned a,b,c,d,regs[12]; memset(regs,0,sizeof regs);
    for(int i=0;i<3;i++){
        if(__get_cpuid(0x80000002+i,&a,&b,&c,&d)){ regs[4*i]=a;regs[4*i+1]=b;regs[4*i+2]=c;regs[4*i+3]=d; }
        else break;
    }
    memcpy(out,regs,48); out[48]=0;
    char*s=out; while(*s==' ')s++; if(s!=out) memmove(out,s,strlen(s)+1);
}
static int g_sha_ni=0, g_x8=0;
static void (*tail_fn)(const uint8_t*,const uint8_t*,uint8_t*) = sha256d_tail_sw;
static void (*tail_x8_fn)(const uint8_t*,const uint8_t*,uint32_t,uint8_t(*)[32]) = sha256d_tail_x8;
/* Keeps the optimiser from deleting benchmark work whose result is unused. */
static volatile uint32_t g_sink=0;

/* ============================================================================
 * 8. HEX HELPERS - Stratum carries all binary fields as hex strings.
 * ==========================================================================*/
static int hexval(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static int hex_decode(const char*s,uint8_t*out,int max){ int n=0; while(s[0]&&s[1]&&n<max){ int a=hexval(s[0]),b=hexval(s[1]); if(a<0||b<0)return -1; out[n++]=(uint8_t)(a*16+b); s+=2; } return n; }
static void hex_encode(const uint8_t*b,int n,char*out){ static const char*d="0123456789abcdef"; for(int i=0;i<n;i++){ out[2*i]=d[b[i]>>4]; out[2*i+1]=d[b[i]&15]; } out[2*n]=0; }

/* ============================================================================
 * 9. MINIMAL JSON PARSER
 * ----------------------------------------------------------------------------
 * A recursive-descent parser covering exactly what Stratum needs: objects,
 * arrays, strings (with escapes), numbers, true/false/null. No dependencies.
 *
 * Node types: 0 null, 1 bool, 2 number, 3 string, 4 array, 5 object.
 * Numbers and booleans share the `num` field - Stratum only ever asks
 * "is this true" or "what is this number".
 *
 * Memory: jparse() allocates a tree; the caller MUST jfree() it. handle_line()
 * does so for every message, so a long-running miner does not leak.
 *
 * `jp` is a file-scope cursor. Only the main thread parses, so this is safe.
 * ==========================================================================*/
typedef struct J{ int t; double num; char*s; struct J**v; char**k; int n; }J;
static const char*jp;
static void jws(void){ while(*jp==' '||*jp=='\t'||*jp=='\n'||*jp=='\r')jp++; }
static J* jnew(int t){ J*j=(J*)calloc(1,sizeof(J)); j->t=t; return j; }
static char* jstr_parse(void){
    jp++; int cap=64,n=0; char*b=(char*)malloc(cap);
    while(*jp&&*jp!='"'){
        char c=*jp++;
        if(c=='\\'&&*jp){
            char e=*jp++;
            switch(e){
                case'n':c='\n';break; case't':c='\t';break; case'r':c='\r';break;
                case'b':c='\b';break; case'f':c='\f';break;
                /* \uXXXX -> UTF-8. Stratum ids are ASCII in practice, but be correct. */
                case'u':{ unsigned u=0; for(int i=0;i<4&&*jp;i++){ char h=*jp++; u=u*16+(h<='9'?h-'0':(h|32)-'a'+10); }
                    if(u<0x80){ c=(char)u; }
                    else if(u<0x800){ if(n+2>=cap){cap*=2;b=(char*)realloc(b,cap);} b[n++]=(char)(0xC0|(u>>6)); c=(char)(0x80|(u&63)); }
                    else { if(n+3>=cap){cap*=2;b=(char*)realloc(b,cap);} b[n++]=(char)(0xE0|(u>>12)); b[n++]=(char)(0x80|((u>>6)&63)); c=(char)(0x80|(u&63)); }
                    break; }
                default:c=e;
            }
        }
        if(n+1>=cap){ cap*=2; b=(char*)realloc(b,cap); } b[n++]=c;
    }
    if(*jp=='"')jp++; b[n]=0; return b;
}
static J* jval(void){
    jws(); char c=*jp;
    if(c=='"'){ J*j=jnew(3); j->s=jstr_parse(); return j; }
    if(c=='{'){ jp++; J*j=jnew(5); int cap=8; j->v=(J**)malloc(cap*sizeof(J*)); j->k=(char**)malloc(cap*sizeof(char*));
        jws(); if(*jp=='}'){jp++;return j;}
        for(;;){ jws(); char*k=jstr_parse(); jws(); if(*jp==':')jp++; J*v=jval();
            if(j->n>=cap){cap*=2;j->v=(J**)realloc(j->v,cap*sizeof(J*));j->k=(char**)realloc(j->k,cap*sizeof(char*));}
            j->k[j->n]=k; j->v[j->n]=v; j->n++; jws();
            if(*jp==','){jp++;continue;} if(*jp=='}'){jp++;break;} break; }
        return j; }
    if(c=='['){ jp++; J*j=jnew(4); int cap=8; j->v=(J**)malloc(cap*sizeof(J*));
        jws(); if(*jp==']'){jp++;return j;}
        for(;;){ J*v=jval(); if(j->n>=cap){cap*=2;j->v=(J**)realloc(j->v,cap*sizeof(J*));} j->v[j->n++]=v; jws();
            if(*jp==','){jp++;continue;} if(*jp==']'){jp++;break;} break; }
        return j; }
    if(c=='t'){ jp+=4; J*j=jnew(1); j->num=1; return j; }
    if(c=='f'){ jp+=5; J*j=jnew(1); j->num=0; return j; }
    if(c=='n'){ jp+=4; return jnew(0); }
    char*e; double d=strtod(jp,&e); jp=e; J*j=jnew(2); j->num=d; return j;
}
static J* jparse(const char*s){ jp=s; return jval(); }
static void jfree(J*j){ if(!j)return; if(j->s)free(j->s); for(int i=0;i<j->n;i++){ if(j->k)free(j->k[i]); jfree(j->v[i]); } free(j->v); free(j->k); free(j); }
static J* jget(J*o,const char*k){ if(!o||o->t!=5)return NULL; for(int i=0;i<o->n;i++) if(!strcmp(o->k[i],k)) return o->v[i]; return NULL; }
static J* jidx(J*a,int i){ if(!a||a->t!=4||i>=a->n)return NULL; return a->v[i]; }
static const char* jstr(J*j){ return j&&j->t==3?j->s:NULL; }
static double jnum(J*j){ return j&&(j->t==2||j->t==1)?j->num:0; }

/* ============================================================================
 * 10. JOB AND SHARED STATE
 * ----------------------------------------------------------------------------
 * A Stratum job does NOT contain a ready-made header. It contains the pieces
 * to build one: the coinbase split in two halves around the extranonce, and
 * the merkle branches needed to fold the coinbase hash up to the root.
 *
 * Fixed-size buffers keep the worker free of malloc: a job is copied by value
 * under the mutex once per epoch change (roughly every 30 s).
 *
 * THE EPOCH MECHANISM
 *   Main bumps g_sh.epoch whenever the job, the difficulty or extranonce1
 *   changes. Workers compare it against their local copy; on a mismatch they
 *   re-read everything and restart their nonce scan. This is how a new block
 *   on the network propagates to the workers within one batch (~65k hashes).
 *
 * MUTEXES
 *   g_state_mtx  protects Shared (job, target, best)
 *   g_send_mtx   serialises socket writes and the g_sock handle
 *   g_ev_mtx     protects the worker -> main event queue
 * ==========================================================================*/
#define COIN_MAX 2048
#define BR_MAX 64
typedef struct {
    char id[128];
    uint8_t prevhash[32];              /* already in header byte order */
    uint8_t cb1[COIN_MAX]; int cb1n;   /* coinbase, part before extranonce */
    uint8_t cb2[COIN_MAX]; int cb2n;   /* coinbase, part after extranonce  */
    uint8_t br[BR_MAX][32]; int nbr;   /* merkle branches, in order */
    uint32_t version,nbits,ntime;
    u256 net_target;                   /* decoded from nbits: real block target */
} Job;
typedef struct {
    int have_job; Job job;
    uint64_t epoch;
    u256 target; double diff;          /* pool SHARE target, much easier */
    uint8_t en1[32]; int en1n; int en2_size;
    u256 best;                         /* smallest hash seen = highest difficulty */
} Shared;
static Shared g_sh;
static mtx_t g_state_mtx, g_send_mtx, g_ev_mtx;
static sock_t g_sock=(sock_t)-1;
static _Atomic uint64_t g_hashes=0, g_accepted=0, g_rejected=0, g_submit_id=100;
static char g_worker[512];             /* "address.worker" sent to the pool */

/* ============================================================================
 * 11. EVENT QUEUE (workers -> main)
 * ----------------------------------------------------------------------------
 * Workers must not print. They push a string here; main drains it and prints
 * it above the status line. Used for the BLOCK FOUND banner.
 * ==========================================================================*/
typedef struct Ev{ char*s; struct Ev*next; } Ev;
static Ev* g_ev_head=NULL;
static void push_event(const char*s){ Ev*e=(Ev*)malloc(sizeof(Ev)); e->s=strdup(s); mtx_lock(&g_ev_mtx); e->next=g_ev_head; g_ev_head=e; mtx_unlock(&g_ev_mtx); }

/* ============================================================================
 * 12. CONSOLE UI
 * ----------------------------------------------------------------------------
 * One live status line, redrawn with '\r' and padded with spaces to erase the
 * previous, longer line. No ANSI escapes: this works in the legacy Windows
 * console as well as in modern terminals.
 *
 * ui_event() clears the line, prints a permanent message, then redraws the
 * status underneath - so events scroll normally while the status stays put.
 * ==========================================================================*/
static char g_status[512]; static int g_width=0;
static void ui_clear(void){ printf("\r%*s\r",g_width,""); g_width=0; }
static void ui_status(const char*s){ int len=(int)strlen(s); int pad=g_width>len?g_width-len:0; printf("\r%s%*s",s,pad,""); fflush(stdout); g_width=len; snprintf(g_status,sizeof g_status,"%s",s); }
static void ui_event(const char*s){ ui_clear(); printf("%s\n",s); if(g_status[0]) ui_status(g_status); fflush(stdout); }

/* ============================================================================
 * 13. STRATUM HANDLERS
 * ----------------------------------------------------------------------------
 * mining.notify params:
 *   [0] job id
 *   [1] prevhash        hex, but with bytes reversed INSIDE each 4-byte word
 *   [2] coinbase1       hex
 *   [3] coinbase2       hex
 *   [4] merkle branches array of hex
 *   [5] version         hex, big-endian
 *   [6] nbits           hex, big-endian (compact network target)
 *   [7] ntime           hex, big-endian
 *   [8] clean_jobs      bool
 *
 * The prevhash word swap is the classic Stratum trap: the header field is the
 * previous block hash in internal (little-endian) order, while Stratum sends
 * it with each 32-bit word byte-reversed. Undo it per word, not globally.
 *
 * Replies are matched by id: 1 = subscribe, 2 = authorize, >=100 = a share.
 * ==========================================================================*/
static int parse_job(J*p,Job*job){
    const char*id=jstr(jidx(p,0)); const char*ph=jstr(jidx(p,1));
    const char*c1=jstr(jidx(p,2)); const char*c2=jstr(jidx(p,3));
    J*br=jidx(p,4); const char*ver=jstr(jidx(p,5)); const char*nb=jstr(jidx(p,6)); const char*nt=jstr(jidx(p,7));
    if(!id||!ph||!c1||!c2||!br||!ver||!nb||!nt) return 0;
    uint8_t phb[32]; if(hex_decode(ph,phb,32)!=32) return 0;
    memset(job,0,sizeof *job);
    snprintf(job->id,sizeof job->id,"%s",id);
    /* Reverse the four bytes inside each 32-bit word. */
    for(int i=0;i<8;i++){
        memcpy(job->prevhash+4*i,phb+4*i,4);
        for(int j=0;j<2;j++){ uint8_t t=job->prevhash[4*i+j]; job->prevhash[4*i+j]=job->prevhash[4*i+3-j]; job->prevhash[4*i+3-j]=t; }
    }
    job->cb1n=hex_decode(c1,job->cb1,COIN_MAX); if(job->cb1n<0)return 0;
    job->cb2n=hex_decode(c2,job->cb2,COIN_MAX); if(job->cb2n<0)return 0;
    if(br->t!=4||br->n>BR_MAX) return 0;
    for(int i=0;i<br->n;i++){ const char*b=jstr(br->v[i]); if(!b||hex_decode(b,job->br[i],32)!=32)return 0; job->nbr++; }
    job->version=(uint32_t)strtoul(ver,NULL,16);
    job->nbits=(uint32_t)strtoul(nb,NULL,16);
    job->ntime=(uint32_t)strtoul(nt,NULL,16);
    job->net_target=target_from_nbits(job->nbits);
    return 1;
}
static void handle_line(const char*line){
    J*root=jparse(line); if(!root) return;
    J*method=jget(root,"method");
    if(method&&method->t==3){
        /* Server-initiated notification. */
        J*p=jget(root,"params");
        if(!strcmp(method->s,"mining.set_difficulty")){
            /* Variable difficulty: the pool retunes the share target to keep
             * our share rate reasonable. Silent - the status line shows it. */
            double d=jnum(jidx(p,0));
            if(d>0){ mtx_lock(&g_state_mtx); g_sh.diff=d; g_sh.target=target_from_diff(d); g_sh.epoch++; mtx_unlock(&g_state_mtx); }
        } else if(!strcmp(method->s,"mining.notify")){
            /* New work. Replacing the job and bumping the epoch makes every
             * worker abandon its current scan on the next batch boundary. */
            Job job; if(parse_job(p,&job)){ mtx_lock(&g_state_mtx); g_sh.job=job; g_sh.have_job=1; g_sh.epoch++; mtx_unlock(&g_state_mtx); }
        }
    } else {
        /* Reply to something we sent. */
        double id=jnum(jget(root,"id"));
        if(id==1){
            /* mining.subscribe result: [subscriptions, extranonce1, extranonce2_size].
             * extranonce1 is per-connection, which is why two machines never
             * search the same space even with identical worker names. */
            J*r=jget(root,"result"); const char*en1=jstr(jidx(r,1)); double sz=jnum(jidx(r,2));
            if(en1){ uint8_t b[32]; int n=hex_decode(en1,b,32);
                if(n>0){ mtx_lock(&g_state_mtx); memcpy(g_sh.en1,b,n); g_sh.en1n=n;
                    g_sh.en2_size=(int)(sz>0?sz:4); if(g_sh.en2_size<1)g_sh.en2_size=1; if(g_sh.en2_size>8)g_sh.en2_size=8;
                    g_sh.epoch++; mtx_unlock(&g_state_mtx); } }
        } else if(id==2){
            J*r=jget(root,"result");
            if(r&&r->t==1&&r->num==1) ui_event("[pool] authorized");
            else ui_event("[pool] authorization REJECTED (check your address)");
        } else if(id>=100){
            /* Share verdict. A rejection is usually "stale": the pool moved
             * to a new job while our share was in flight. A few % is normal. */
            J*r=jget(root,"result");
            if(r&&r->t==1&&r->num==1){ uint64_t a=atomic_fetch_add(&g_accepted,1)+1; char m[160]; snprintf(m,sizeof m,"[share] ACCEPTED (id %.0f) - total A: %llu",id,(unsigned long long)a); ui_event(m); }
            else { uint64_t rj=atomic_fetch_add(&g_rejected,1)+1; char m[200]; snprintf(m,sizeof m,"[share] rejected (id %.0f) - total R: %llu",id,(unsigned long long)rj); ui_event(m); }
        }
    }
    jfree(root);
}

/* ============================================================================
 * 14. MINING WORKER
 * ----------------------------------------------------------------------------
 * Search space partitioning:
 *   extranonce2 = tid, tid + nthreads, tid + 2*nthreads, ...
 *   For each extranonce2 the worker scans the whole 32-bit nonce range.
 *   Threads therefore never overlap, and no coordination is needed.
 *
 * Per extranonce2 (rare - once per ~4 billion hashes, or on a new job):
 *   build coinbase, fold the merkle root, assemble the header, compute midstate.
 *
 * Per nonce (the hot loop):
 *   patch the nonce into tail[12..15], hash, update best, compare with targets.
 *
 * Batching: 65536 hashes between checks of the shared state. That keeps mutex
 * traffic negligible while still reacting to a new job within ~milliseconds.
 * ==========================================================================*/
typedef struct { int tid,n; } arg_t;

/* mining.submit params: worker, job id, extranonce2, ntime, nonce.
 * ntime and nonce are sent as big-endian hex of their numeric value. */
static void submit_share(const char*jobid,const char*en2hex,uint32_t ntime,uint32_t nonce){
    uint64_t id=atomic_fetch_add(&g_submit_id,1);
    char msg[1024];
    int len=snprintf(msg,sizeof msg,
        "{\"id\":%llu,\"method\":\"mining.submit\",\"params\":[\"%s\",\"%s\",\"%s\",\"%08x\",\"%08x\"]}\n",
        (unsigned long long)id,g_worker,jobid,en2hex,ntime,nonce);
    if(len<0||len>=(int)sizeof msg) return;
    mtx_lock(&g_send_mtx); if(g_sock!=(sock_t)-1) net_send_all(g_sock,msg,len); mtx_unlock(&g_send_mtx);
}
/* A hash below the NETWORK target is a real block. We still submit it as a
 * share - the pool assembles and broadcasts the block. The dump is a souvenir
 * and a debugging aid. */
static void block_found(const Job*job,const uint8_t hdr[80],const uint8_t *coinbase,int cbn,
                        const char*en1hex,const char*en2hex,uint32_t nonce,const uint8_t hash[32]){
    char hh[65]; uint8_t rev[32]; for(int i=0;i<32;i++)rev[i]=hash[31-i]; hex_encode(rev,32,hh);
    char hdrhex[161]; hex_encode(hdr,80,hdrhex);
    char*cbhex=(char*)malloc(2*(size_t)cbn+1); hex_encode(coinbase,cbn,cbhex);
    FILE*f=fopen("BLOCK_FOUND.txt","w");
    if(f){ fprintf(f,"job: %s\nnonce: %08x\nntime: %08x\nextranonce1: %s\nextranonce2: %s\nblock_hash: %s\nheader_hex: %s\ncoinbase_hex: %s\n",
        job->id,nonce,job->ntime,en1hex,en2hex,hh,hdrhex,cbhex); fclose(f); }
    free(cbhex);
    char banner[512]; snprintf(banner,sizeof banner,
        "\n==============================\n!!! BLOCK FOUND !!!\nhash:  %s\nnonce: %08x\ndump:  BLOCK_FOUND.txt\nshare submitted - the pool broadcasts the block\n==============================",hh,nonce);
    push_event(banner);
}
static void worker(void*vp){
    arg_t a=*(arg_t*)vp;
    uint64_t epoch=UINT64_MAX;         /* force a load on the first iteration */
    Job job; int have_job=0;
    u256 target; uint8_t en1[32]; int en1n=0,en2_size=4;
    uint64_t en2=a.tid; uint32_t nonce=0;
    uint8_t mid[32],tail[16],hdr[80],coinbase[2*COIN_MAX+64]; int cbn=0;
    char en2hex[32],en1hex[65];
    int have_prefix=0;
    u256 best; for(int i=0;i<4;i++)best.l[i]=UINT64_MAX;
    uint64_t local=0;                  /* local counter, flushed per batch */
    for(;;){
        /* --- refresh shared state if anything changed --- */
        mtx_lock(&g_state_mtx);
        if(g_sh.epoch!=epoch){
            epoch=g_sh.epoch; have_job=g_sh.have_job; job=g_sh.job; target=g_sh.target;
            memcpy(en1,g_sh.en1,g_sh.en1n); en1n=g_sh.en1n; en2_size=g_sh.en2_size;
            en2=a.tid; nonce=0; have_prefix=0;
        }
        if(less256(&best,&g_sh.best)) g_sh.best=best;
        mtx_unlock(&g_state_mtx);
        if(!have_job||en1n==0){ sleep_ms(200); continue; }   /* not subscribed yet */

        /* --- build the prefix: once per extranonce2 --- */
        if(!have_prefix){
            uint64_t mx=(en2_size>=8)?UINT64_MAX:(1ULL<<(8*en2_size)); en2%=mx;
            uint8_t en2b[8]; for(int i=0;i<en2_size;i++)en2b[i]=(uint8_t)(en2>>(8*i));
            hex_encode(en2b,en2_size,en2hex); hex_encode(en1,en1n,en1hex);
            /* coinbase = coinb1 || extranonce1 || extranonce2 || coinb2 */
            cbn=0;
            memcpy(coinbase+cbn,job.cb1,job.cb1n); cbn+=job.cb1n;
            memcpy(coinbase+cbn,en1,en1n);         cbn+=en1n;
            memcpy(coinbase+cbn,en2b,en2_size);    cbn+=en2_size;
            memcpy(coinbase+cbn,job.cb2,job.cb2n); cbn+=job.cb2n;
            /* Merkle root: start from the coinbase txid, then for each branch
             * hash (current || branch). Branches are already in internal byte
             * order - no swapping here. An empty branch list means the block
             * contains only the coinbase, and the root is the txid itself. */
            uint8_t mr[32]; sha256d(coinbase,cbn,mr);
            for(int i=0;i<job.nbr;i++){ uint8_t b64[64]; memcpy(b64,mr,32); memcpy(b64+32,job.br[i],32); sha256d(b64,64,mr); }
            /* 80-byte header, all multi-byte fields little-endian. */
            memset(hdr,0,80);
            uint32_t v=job.version; memcpy(hdr,&v,4);
            memcpy(hdr+4,job.prevhash,32);
            memcpy(hdr+36,mr,32);
            uint32_t nt=job.ntime; memcpy(hdr+68,&nt,4);
            uint32_t nb=job.nbits; memcpy(hdr+72,&nb,4);
            midstate(hdr,mid);              /* absorb header[0..63] once */
            memcpy(tail,hdr+64,16);         /* merkle tail, ntime, nbits, nonce */
            have_prefix=1;
        }

        if(g_x8){
            /* --- AVX2 path: 8 nonces per call --- */
            for(unsigned i=0;i<8192u;i++){          /* 8192 * 8 = 65536 hashes */
                uint8_t outs[8][32];
                tail_x8_fn(mid,tail,nonce,outs);
                local+=8;
                for(int l=0;l<8;l++){
                    const uint8_t*out=outs[l];
                    /* Cheap filter: only build the full u256 when the top
                     * limb could possibly beat our best. */
                    uint64_t top; memcpy(&top,out+24,8);
                    if(top<=best.l[3]){ u256 h; for(int k=0;k<4;k++)memcpy(&h.l[k],out+k*8,8); if(less256(&h,&best))best=h; }
                    if(meets(out,&target)){
                        uint32_t nn=nonce+(uint32_t)l;
                        memcpy(hdr+76,&nn,4);
                        submit_share(job.id,en2hex,job.ntime,nn);
                        /* The network target is always stricter than the pool
                         * target, so this test only runs inside a share hit. */
                        if(meets(out,&job.net_target)) block_found(&job,hdr,coinbase,cbn,en1hex,en2hex,nn,out);
                    }
                }
                nonce+=8;
                /* Nonce space exhausted -> move to the next extranonce2. */
                if(nonce==0){ en2+=a.n; have_prefix=0; break; }
            }
        } else {
            /* --- scalar / SHA-NI path: one nonce per call --- */
            for(unsigned i=0;i<65536u;i++){
                memcpy(tail+12,&nonce,4);
                uint8_t out[32]; tail_fn(mid,tail,out);
                local++;
                uint64_t top; memcpy(&top,out+24,8);
                if(top<=best.l[3]){ u256 h; for(int k=0;k<4;k++)memcpy(&h.l[k],out+k*8,8); if(less256(&h,&best))best=h; }
                if(meets(out,&target)){
                    memcpy(hdr+76,&nonce,4);
                    submit_share(job.id,en2hex,job.ntime,nonce);
                    if(meets(out,&job.net_target)) block_found(&job,hdr,coinbase,cbn,en1hex,en2hex,nonce,out);
                }
                nonce++;
                if(nonce==0){ en2+=a.n; have_prefix=0; break; }
            }
        }
        /* Publish counters once per batch, not once per hash. */
        atomic_fetch_add(&g_hashes,local); local=0;
        mtx_lock(&g_state_mtx); if(less256(&best,&g_sh.best)) g_sh.best=best; mtx_unlock(&g_state_mtx);
    }
}

/* ============================================================================
 * 15. THREAD SPAWN HELPERS
 * ----------------------------------------------------------------------------
 * Win32 and pthreads have different entry-point signatures; a trampoline
 * adapts both to a plain void f(void*).
 * ==========================================================================*/
#ifdef _WIN32
static DWORD WINAPI tramp(LPVOID p){ worker(p); return 0; }
static int  spawn(thr_t*t,void*a){ *t=CreateThread(NULL,0,tramp,a,0,NULL); return *t==NULL; }
static void jointh(thr_t t){ WaitForSingleObject(t,INFINITE); CloseHandle(t); }
#else
static void* tramp(void*p){ worker(p); return NULL; }
static int  spawn(thr_t*t,void*a){ return pthread_create(t,NULL,tramp,a); }
static void jointh(thr_t t){ pthread_join(t,NULL); }
#endif

/* ============================================================================
 * 16. ENGINE BENCHMARK (tuning)
 * ----------------------------------------------------------------------------
 * WHY AT N THREADS AND NOT SINGLE-THREADED
 *   The best engine depends on how many threads you run:
 *     - SHA-NI is latency-bound, so SMT gives it a large boost (~66%).
 *     - AVX2 already saturates the vector ports, so SMT adds little (~34%).
 *     - On hybrid CPUs the E-cores execute 256-bit ops in two passes but run
 *       SHA-NI natively, which flips the ranking again at full thread count.
 *   A single-threaded microbenchmark therefore picks the wrong engine.
 *   We benchmark with exactly the thread count the user asked for.
 *
 * The benchmark runs the same inner work as mining (hash + best filter +
 * target compare) so the numbers reflect reality, not just the hash core.
 *
 * All threads spin on b_start until every thread exists, so thread creation
 * time is not counted, then run until main sets b_stop.
 * ==========================================================================*/
static _Atomic int b_start=0, b_stop=0;
static _Atomic uint64_t b_hashes=0;
static int b_mode=0;                     /* 0 scalar, 1 SHA-NI, 2 AVX2 */
static u256 b_target={{0,0,0,0}};        /* impossible target: never fires */

static inline void bench_check(const uint8_t*out,u256*best,unsigned*sink){
    uint64_t top; memcpy(&top,out+24,8);
    if(top<=best->l[3]){ u256 h; for(int k=0;k<4;k++)memcpy(&h.l[k],out+k*8,8); if(less256(&h,best))*best=h; }
    if(meets(out,&b_target)) (*sink)++;
}
static void bench_worker(void*vp){
    (void)vp;
    uint8_t h[80],mid[32],tail[16],out[32],outs[8][32];
    for(int i=0;i<80;i++) h[i]=(uint8_t)(i*3+1);
    midstate(h,mid); memcpy(tail,h+64,16);
    u256 best; for(int i=0;i<4;i++)best.l[i]=UINT64_MAX;
    uint32_t n=0; uint64_t local=0; unsigned sink=0;
    while(!atomic_load(&b_start)) sleep_ms(1);
    while(!atomic_load(&b_stop)){
        if(b_mode==2){
            for(int i=0;i<256;i++){
                sha256d_tail_x8(mid,tail,n,outs);
                for(int l=0;l<8;l++) bench_check(outs[l],&best,&sink);
                n+=8;
            }
            local+=2048;
        } else {
            for(int i=0;i<2048;i++){
                memcpy(tail+12,&n,4);
                if(b_mode==1) sha256d_tail(mid,tail,out); else sha256d_tail_sw(mid,tail,out);
                bench_check(out,&best,&sink);
                n++;
            }
            local+=2048;
        }
    }
    g_sink+=sink;                        /* defeat dead-code elimination */
    atomic_fetch_add(&b_hashes,local);
}
#ifdef _WIN32
static DWORD WINAPI btramp(LPVOID p){ bench_worker(p); return 0; }
static int bspawn(thr_t*t){ *t=CreateThread(NULL,0,btramp,NULL,0,NULL); return *t==NULL; }
#else
static void* btramp(void*p){ bench_worker(p); return NULL; }
static int bspawn(thr_t*t){ return pthread_create(t,NULL,btramp,NULL); }
#endif
static double bench_engine_mt(int mode,int nthr,double budget){
    static thr_t bth[4096];
    b_mode=mode;
    atomic_store(&b_start,0); atomic_store(&b_stop,0); atomic_store(&b_hashes,0);
    for(int i=0;i<nthr;i++) bspawn(&bth[i]);
    sleep_ms(30);                        /* let every thread reach the gate */
    double t0=now_sec();
    atomic_store(&b_start,1);
    sleep_ms((int)(budget*1000.0));
    atomic_store(&b_stop,1);
    for(int i=0;i<nthr;i++) jointh(bth[i]);
    double dt=now_sec()-t0;
    return (double)atomic_load(&b_hashes)/dt;   /* aggregate hashes/second */
}

/* ============================================================================
 * 17. SELF-TEST
 * ----------------------------------------------------------------------------
 * Runs before any mining. Two known-answer SHA-256d digests, computed with an
 * independent implementation, for two 80-byte inputs.
 *
 * Checking the fast paths against our own software code alone would not be
 * enough: a shared bug would cancel out. The hardcoded vectors close that hole.
 *
 * The AVX2 path is tested at three nonce bases, including 0xFFFFFFF8 - the
 * last full group before the 32-bit nonce wraps - to catch lane arithmetic
 * mistakes at the boundary.
 *
 * On failure the program exits rather than submitting invalid shares.
 * ==========================================================================*/
static const char* KAT[2]={
 "852c98044fb00507122ff63bda7b529566348fc204f72b00dff1afd7b40501e4",
 "957e2df158e91846019ea6d27e05b3d18c0abb09e65327a615ea4c17d529f99b"
};
static int selftest(void){
    for(int t=0;t<2;t++){
        uint8_t h[80],exp[32],o[32],mid[32];
        for(int i=0;i<80;i++) h[i]= t ? (uint8_t)(i*7+3) : (uint8_t)i;
        if(hex_decode(KAT[t],exp,32)!=32) return 0;
        sha256d(h,80,o);                      if(memcmp(o,exp,32)) return 0;
        midstate(h,mid); tail_fn(mid,h+64,o); if(memcmp(o,exp,32)) return 0;
        if(g_sha_ni){ sha256d_80(h,o);        if(memcmp(o,exp,32)) return 0; }
    }
    if(g_x8){
        uint8_t h[80],mid[32],outs[8][32],exp[32];
        for(int i=0;i<80;i++) h[i]=(uint8_t)i;
        midstate(h,mid);
        uint32_t bases[3]={0u,0x01020304u,0xFFFFFFF8u};
        for(int b=0;b<3;b++){
            tail_x8_fn(mid,h+64,bases[b],outs);
            for(int l=0;l<8;l++){
                uint32_t nn=bases[b]+(uint32_t)l;
                memcpy(h+76,&nn,4); sha256d(h,80,exp);
                if(memcmp(outs[l],exp,32)) return 0;
            }
        }
    }
    return 1;
}

/* ============================================================================
 * 18. CLI AND MAIN
 * ----------------------------------------------------------------------------
 * -a and -p are REQUIRED. There is no default pool and no default payout
 * address anywhere in this program. The address printed at the bottom of the
 * help text is a donation address and is never used to mine.
 *
 * Startup order matters:
 *   parse args -> optional delay -> engine tuning -> self-test -> mine.
 * The delay comes BEFORE tuning so that, when autostarted with Windows, the
 * benchmark is not distorted by boot-time load. During the delay the process
 * only sleeps - it does not touch the CPU.
 * ==========================================================================*/
static void usage(void){
    printf("btc-miner-c %s - CPU Bitcoin solo miner (Stratum v1, C + x86-64 asm)\n\n",VERSION);
    printf("REQUIRED:\n");
    printf("  -a ADDR        Bitcoin payout address (no default)\n");
    printf("  -p HOST:PORT   Stratum pool endpoint (no default)\n\n");
    printf("OPTIONAL:\n");
    printf("  -w NAME        Worker suffix appended to the address (default: cpu1)\n");
    printf("  -t N           Mining threads (default: all logical CPUs)\n");
    printf("  -x PASS        Pool password (default: x)\n");
    printf("  -e ENGINE      auto | shani | avx2 | scalar (default: auto)\n");
    printf("  -d MIN         Startup delay in minutes, fractional allowed (default: 0)\n");
    printf("  -h             Show this help\n\n");
    printf("EXAMPLES:\n");
    printf("  btc-miner-c -a bc1q... -p solo.ckpool.org:3333 -t 6\n");
    printf("  btc-miner-c -a bc1q... -p solo.ckpool.org:3333 -t 8 -d 5 -w rig1\n");
    printf("  btc-miner-c -a bc1q... -p solo.ckpool.org:3333 -t 8 -e avx2\n\n");
    printf("WARNING: CPU mining of Bitcoin is a lottery, not an income source.\n");
    printf("         Expect years of runtime before a single pool share, and\n");
    printf("         astronomically long odds of ever finding a block.\n\n");
    /* Donation address: help text only. Never used as a default anywhere. */
    printf("Donations (BTC): bc1q563zveamrcj3mu5gjlcpcv8ythuhjha9ychr6r\n");
}

int main(int argc,char**argv){
#ifdef _WIN32
    SetConsoleOutputCP(65001);
#endif
    net_init();
    mtx_init(&g_state_mtx); mtx_init(&g_send_mtx); mtx_init(&g_ev_mtx);

    char addr[256]="";           /* required, deliberately empty */
    char pool[256]="";           /* required, deliberately empty */
    char wsuf[128]="cpu1";
    char pass[128]="x";
    char eng[32]="auto";
    double delay_min=0.0;
    int n=cpu_count();

    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"-h")||!strcmp(argv[i],"--help")){usage();return 0;}
        if(i+1>=argc){fprintf(stderr,"Error: missing value after %s\n\n",argv[i]);usage();return 1;}
        if(!strcmp(argv[i],"-a"))snprintf(addr,sizeof addr,"%s",argv[++i]);
        else if(!strcmp(argv[i],"-p"))snprintf(pool,sizeof pool,"%s",argv[++i]);
        else if(!strcmp(argv[i],"-w"))snprintf(wsuf,sizeof wsuf,"%s",argv[++i]);
        else if(!strcmp(argv[i],"-x"))snprintf(pass,sizeof pass,"%s",argv[++i]);
        else if(!strcmp(argv[i],"-e"))snprintf(eng,sizeof eng,"%s",argv[++i]);
        else if(!strcmp(argv[i],"-d"))delay_min=atof(argv[++i]);
        else if(!strcmp(argv[i],"-t"))n=atoi(argv[++i]);
        else {fprintf(stderr,"Error: unknown option %s\n\n",argv[i]);usage();return 1;}
    }
    if(addr[0]=='\0'||pool[0]=='\0'){
        fprintf(stderr,"Error: -a <address> and -p <host:port> are required.\n");
        fprintf(stderr,"This build has no built-in pool and no built-in payout address.\n\n");
        usage(); return 1;
    }
    /* Cheap sanity checks; the pool does the real address validation. */
    if(strlen(addr)<26){ fprintf(stderr,"Error: address looks too short: %s\n",addr); return 1; }
    if(!strchr(pool,':')){ fprintf(stderr,"Error: pool must be HOST:PORT\n"); return 1; }
    if(n<1)n=1; if(n>4096)n=4096;
    if(delay_min<0.0)delay_min=0.0;
    if(delay_min>10080.0)delay_min=10080.0;      /* cap at one week */
    snprintf(g_worker,sizeof g_worker,"%s.%s",addr,wsuf);

    __builtin_cpu_init();
    int have_sha=cpu_has_sha();
    int have_avx2=__builtin_cpu_supports("avx2");
    { char brand[64]; cpu_brand(brand);
      printf("[cpu] %s\n",brand);
      printf("[cpu] SHA-NI: %s | AVX2: %s | threads: %d\n",have_sha?"yes":"no",have_avx2?"yes":"no",n); }

    /* ---- startup delay: CPU stays completely idle ---- */
    if(delay_min>0.0){
        printf("[wait] startup delay %.1f min - waiting for the system to settle\n",delay_min);
        double t_end=now_sec()+delay_min*60.0;
        for(;;){
            double left=t_end-now_sec();
            if(left<=0.0) break;
            int s=(int)(left+0.999);
            char wl[256];
            snprintf(wl,sizeof wl,"[wait] starting in %02d:%02d:%02d   (delay %.1f min, CPU idle)",
                     s/3600,(s%3600)/60,s%60,delay_min);
            ui_status(wl);
            sleep_ms(left>1.0?1000:(int)(left*1000.0)+1);
        }
        ui_clear(); g_status[0]=0;   /* drop the countdown from the saved status */
        printf("[wait] delay finished - starting\n"); fflush(stdout);
    }

    /* ---- engine selection ---- */
    if(!strcmp(eng,"shani")){
        if(!have_sha){fprintf(stderr,"Error: SHA-NI is not available on this CPU\n");return 1;}
        g_sha_ni=1; g_x8=0;
    } else if(!strcmp(eng,"avx2")){
        if(!have_avx2){fprintf(stderr,"Error: AVX2 is not available on this CPU\n");return 1;}
        g_sha_ni=0; g_x8=1;
    } else if(!strcmp(eng,"scalar")){ g_sha_ni=0; g_x8=0; }
    else if(!strcmp(eng,"auto")){
        printf("[tune] benchmarking on %d thread(s), %.2f s per engine...\n",n,TUNE_SEC);
        double best=-1.0; int pick=0;
        double r0=bench_engine_mt(0,n,TUNE_SEC);
        printf("[tune] scalar : %8.2f MH/s\n",r0/1e6); best=r0; pick=0;
        if(have_sha){ double r=bench_engine_mt(1,n,TUNE_SEC);
            printf("[tune] shani  : %8.2f MH/s\n",r/1e6); if(r>best){best=r;pick=1;} }
        if(have_avx2){ double r=bench_engine_mt(2,n,TUNE_SEC);
            printf("[tune] avx2 x8: %8.2f MH/s\n",r/1e6); if(r>best){best=r;pick=2;} }
        g_sha_ni=(pick==1); g_x8=(pick==2);
        printf("[tune] selected: %s (%.2f MH/s)\n",
               pick==1?"shani":(pick==2?"avx2 x8":"scalar"), best/1e6);
    } else { fprintf(stderr,"Error: unknown engine: %s\n",eng); return 1; }
    tail_fn = g_sha_ni ? sha256d_tail : sha256d_tail_sw;
    printf("[cpu] engine: %s\n", g_sha_ni?"asm SHA-NI + midstate":(g_x8?"AVX2 x8 multi-buffer + midstate":"C scalar + midstate"));

    if(!selftest()){ fprintf(stderr,"[selftest] FAILED - hash mismatch against reference vectors, exiting\n"); return 2; }
    printf("[selftest] OK (reference vectors%s%s)\n", g_sha_ni?", asm":"", g_x8?", x8 lanes":"");

    memset(&g_sh,0,sizeof g_sh);
    g_sh.target=target_from_diff(1.0); g_sh.diff=1.0; g_sh.en2_size=4;
    for(int i=0;i<4;i++)g_sh.best.l[i]=UINT64_MAX;

    printf("btc-miner-c %s: pool %s | worker %s | threads %d\n",VERSION,pool,g_worker,n);
    static thr_t th[4096]; static arg_t ar[4096];
    for(int i=0;i<n;i++){ ar[i].tid=i; ar[i].n=n; spawn(&th[i],&ar[i]); }

    char host[256],port[32];
    { const char*c=strchr(pool,':');
      size_t hl=c-pool; if(hl>=sizeof host)hl=sizeof host-1; memcpy(host,pool,hl); host[hl]=0; snprintf(port,sizeof port,"%s",c+1); }

    /* ---- outer loop: connect, mine, reconnect on failure ---- */
    double t0=now_sec();
    for(;;){
        sock_t s=net_connect(host,port);
        if(s==(sock_t)-1){ ui_event("[net] connection failed; retry in 5 s"); sleep_ms(5000); continue; }
        mtx_lock(&g_send_mtx); g_sock=s; mtx_unlock(&g_send_mtx);
        /* Invalidate the session: workers idle until a new subscribe+notify. */
        mtx_lock(&g_state_mtx); g_sh.have_job=0; g_sh.en1n=0; g_sh.epoch++; mtx_unlock(&g_state_mtx);

        char sub[256],auth[1024];
        int sl=snprintf(sub,sizeof sub,"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"btc-miner-c/%s\"]}\n",VERSION);
        int al=snprintf(auth,sizeof auth,"{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}\n",g_worker,pass);
        if(!net_send_all(s,sub,sl)||!net_send_all(s,auth,al)){
            net_close(s); mtx_lock(&g_send_mtx); g_sock=(sock_t)-1; mtx_unlock(&g_send_mtx); sleep_ms(5000); continue; }
        ui_event("[net] connected");

        char buf[65536]; int bn=0;
        uint64_t prev=atomic_load(&g_hashes); double pt=now_sec(), ema=0, last=now_sec();
        int alive=1;
        while(alive){
            /* 1. print anything the workers reported */
            mtx_lock(&g_ev_mtx); Ev*e=g_ev_head; g_ev_head=NULL; mtx_unlock(&g_ev_mtx);
            while(e){ ui_event(e->s); Ev*nx=e->next; free(e->s); free(e); e=nx; }
            /* 2. read whatever arrived; timeout is normal, not an error */
            int k=net_recv(s,buf+bn,(int)sizeof buf-bn-1);
            if(k==0){ ui_event("[net] pool closed the connection"); alive=0; }
            else if(k<0){ if(!recv_timeout_ok()){ ui_event("[net] read error"); alive=0; } }
            else {
                /* 3. split the buffer into complete lines. A partial line
                 *    stays in the buffer until the rest arrives. */
                bn+=k; buf[bn]=0;
                char*nl;
                while((nl=strchr(buf,'\n'))){
                    *nl=0; handle_line(buf);
                    int rem=bn-(int)(nl+1-buf); memmove(buf,nl+1,rem); bn=rem; buf[bn]=0;
                }
                if(bn>=(int)sizeof buf-1) bn=0;   /* oversized garbage: drop */
            }
            /* 4. redraw the status line once a second */
            double now=now_sec();
            if(now-last>=1.0){
                uint64_t tot=atomic_load(&g_hashes);
                double inst=(double)(tot-prev)/(now-pt);
                ema = ema==0?inst:ema*0.7+inst*0.3;   /* smooth the display */
                prev=tot; pt=now; last=now;
                mtx_lock(&g_state_mtx);
                double diff=g_sh.diff; u256 best=g_sh.best;
                char jid[128]; snprintf(jid,sizeof jid,"%s",g_sh.have_job?g_sh.job.id:"-");
                mtx_unlock(&g_state_mtx);
                char sp[32],ct[32],bd[32]; fmt_speed(ema,sp); fmt_count(tot,ct); fmt_diff(hash_diff(&best),bd);
                jid[8]=0;
                double el=now-t0; int hh=(int)el/3600,mm=((int)el%3600)/60,ss=(int)el%60;
                char line[512];
                snprintf(line,sizeof line,"[%02d:%02d:%02d] %-12s | %-9s hashes | A/R %llu/%llu | diff %.0f | best %s | job %s",
                    hh,mm,ss,sp,ct,(unsigned long long)atomic_load(&g_accepted),(unsigned long long)atomic_load(&g_rejected),diff,bd,jid);
                ui_status(line);
            }
        }
        mtx_lock(&g_send_mtx); net_close(s); g_sock=(sock_t)-1; mtx_unlock(&g_send_mtx);
        mtx_lock(&g_state_mtx); g_sh.have_job=0; g_sh.epoch++; mtx_unlock(&g_state_mtx);
        ui_event("[net] connection lost");
        ui_status("[net] reconnecting in 5 s...");
        sleep_ms(5000);
    }
    return 0;
}