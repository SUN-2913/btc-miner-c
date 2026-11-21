/* ============================================================================
 * sha256ni.S - SHA-256d (double SHA-256) in x86-64 assembly using SHA-NI
 * ----------------------------------------------------------------------------
 * Exported functions:
 *
 *   void sha256d_80(const uint8_t in[80], uint8_t out[32])
 *       Full double SHA-256 of an 80-byte Bitcoin block header.
 *       Cost: 3 compressions (2 for the header, 1 for the 32-byte rehash).
 *
 *   void sha256d_tail(const uint8_t mid[32], const uint8_t tail[16],
 *                     uint8_t out[32])
 *       Same result, but the first 64-byte block has already been absorbed
 *       into `mid` (the "midstate"). Cost: 2 compressions.
 *       This is the midstate optimisation: the first 64 header bytes are
 *       constant for a given job + extranonce2, so we hash them once and
 *       reuse the resulting state for every nonce.
 *
 * Availability: SHA-NI exists on Intel Ice Lake / Rocket Lake and newer, and
 * on AMD Zen and newer. Older CPUs (e.g. Comet Lake) will raise SIGILL /
 * STATUS_ILLEGAL_INSTRUCTION. The C side checks CPUID before calling these.
 *
 * ----------------------------------------------------------------------------
 * THE MAIN SHA-NI GOTCHA
 * ----------------------------------------------------------------------------
 * SHA256RNDS2 takes THREE operands, but only two are written in assembly:
 *
 *     sha256rnds2 dst, src        ; implicit third operand is XMM0
 *
 * XMM0 must hold the round constant pair K[t], K[t+1]. Therefore XMM0 CANNOT
 * be used to keep hash state - it would be overwritten. Register allocation:
 *
 *   XMM0        XFER: W[t] + K[t]  (implicit rnds2 operand)
 *   XMM1        STATE0: words A, B, E, F
 *   XMM2        STATE1: words C, D, G, H
 *   XMM3..XMM6  MSG0..MSG3: the 16 message words, 4 words per register
 *   XMM7        byte-reversal mask for pshufb
 *   XMM8, XMM9  scratch
 *
 * ----------------------------------------------------------------------------
 * WHY THE STATE IS SPLIT AS ABEF / CDGH
 * ----------------------------------------------------------------------------
 * SHA256RNDS2 reads ABEF from src and CDGH from dst, and writes the new ABEF
 * into dst. It looks as if CDGH is lost. The trick is a property of SHA-256
 * itself: after TWO rounds the new (C,D,G,H) equal the old (A,B,E,F) - the
 * words simply shift along the pipeline. So the next instruction swaps the
 * roles and no data movement is needed:
 *
 *     sha256rnds2 xmm2, xmm1   ; xmm2 <- new ABEF; xmm1 (old ABEF) = new CDGH
 *     sha256rnds2 xmm1, xmm2   ; and back
 *
 * 64 rounds = 32 instructions = an even count, so at the end of a block the
 * layout is back to the original: xmm1 = ABEF, xmm2 = CDGH.
 *
 * ----------------------------------------------------------------------------
 * BYTE ORDER
 * ----------------------------------------------------------------------------
 * SHA-256 operates on 32-bit words; message memory is big-endian.
 *   Input:  pshufb with mask [3,2,1,0, 7,6,5,4, ...] turns BE bytes into the
 *           native little-endian dwords the instructions expect.
 *   Output: pshufb again, to produce the standard hash byte order.
 *   Padding length field is big-endian too, hence the bswap before storing.
 *
 * The midstate produced by the C function midstate() is stored as native
 * little-endian dwords (NOT as a printable hash), which is exactly what
 * INIT_STATE_MEM expects - same layout as the IV constant below.
 *
 * ----------------------------------------------------------------------------
 * ABI AND STACK
 * ----------------------------------------------------------------------------
 * SysV AMD64:  args in RDI, RSI, RDX.  All XMM registers are caller-saved.
 * Win64:       args in RCX, RDX, R8.   RDI, RSI and XMM6-XMM15 are callee-saved,
 *              so they are pushed/saved and restored around the body.
 *
 * On entry RSP % 16 == 8 (the call pushed an 8-byte return address).
 *   SysV:  sub 440                       -> RSP % 16 == 0
 *   Win64: push rdi, push rsi, sub 64, sub 440 -> RSP % 16 == 0
 * All memory operands use movdqu anyway, so alignment is not a correctness
 * requirement here - PE/COFF section alignment differs from ELF and movdqa
 * on a misaligned constant would fault. movdqu costs nothing when aligned.
 *
 * Stack frame layout (440 bytes):
 *   [rsp +   0 .. 255]  XFER: 64 dwords of W[t]+K[t]
 *   [rsp + 256 .. 287]  saved state for the feed-forward addition
 *   [rsp + 288 .. 351]  padded second block (tail16 + padding + length)
 *   [rsp + 352 .. 415]  padded third block (first hash + padding + length)
 *
 * ----------------------------------------------------------------------------
 * KNOWN LIMITATION
 * ----------------------------------------------------------------------------
 * The message schedule is computed in a separate pass into the stack, then
 * the rounds read it back. A fused one-pass schedule (as in the Linux kernel
 * and RustCrypto) avoids those 32 stack round-trips per block and is faster.
 * Kept two-pass here because it is far easier to follow and to verify.
 * ==========================================================================*/

.intel_syntax noprefix
.text

/* ----------------------------------------------------------------------------
 * SHA256_BLOCK src, off
 * One compression function. Absorbs the 64 bytes at [src+off] into the state
 * held in xmm1/xmm2, then adds the feed-forward (SHA-256 is Merkle-Damgard:
 * the output is input_state + working_state).
 * --------------------------------------------------------------------------*/
.macro SHA256_BLOCK src, off
    /* Save the incoming state; it is added back at the end. */
    movdqu [rsp+256], xmm1
    movdqu [rsp+272], xmm2

    /* Load the 16 message words and convert BE memory -> native dwords. */
    movdqu xmm3, [\src+\off+0]
    movdqu xmm4, [\src+\off+16]
    movdqu xmm5, [\src+\off+32]
    movdqu xmm6, [\src+\off+48]
    pshufb xmm3, xmm7
    pshufb xmm4, xmm7
    pshufb xmm5, xmm7
    pshufb xmm6, xmm7

    /* ---- Pass 1: message schedule ------------------------------------------
     * W[0..15] come straight from the block. For t >= 16:
     *     W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
     * SHA-NI splits this into three steps:
     *     sha256msg1 dst, src   adds the sigma0(W[t-15]) part
     *     palignr + paddd       adds the W[t-7] part
     *     sha256msg2 dst, src   adds the sigma1(W[t-2]) part
     * Each group of 4 registers covers 16 words; we emit W+K for the rounds
     * pass, then roll the registers forward to the next 16 words.
     * ----------------------------------------------------------------------*/
    .set g, 0
    .rept 4
        movdqu xmm8, [rip+K256+g*64+0]
        movdqu xmm9, xmm3
        paddd  xmm9, xmm8
        movdqu [rsp+g*64+0], xmm9
        movdqu xmm8, [rip+K256+g*64+16]
        movdqu xmm9, xmm4
        paddd  xmm9, xmm8
        movdqu [rsp+g*64+16], xmm9
        movdqu xmm8, [rip+K256+g*64+32]
        movdqu xmm9, xmm5
        paddd  xmm9, xmm8
        movdqu [rsp+g*64+32], xmm9
        movdqu xmm8, [rip+K256+g*64+48]
        movdqu xmm9, xmm6
        paddd  xmm9, xmm8
        movdqu [rsp+g*64+48], xmm9

        /* The last group needs no schedule update - there is no W[64]. */
        .if g < 3
            /* MSG0 -> W[16..19]: uses old MSG1 for sigma0, MSG2:MSG3 for W[t-7],
             * MSG3 for sigma1. Order matters: each update must still see the
             * OLD values of the registers it depends on. */
            sha256msg1 xmm3, xmm4
            movdqu xmm9, xmm6
            palignr xmm9, xmm5, 4      /* W[9..12] straddles MSG2 and MSG3 */
            paddd xmm3, xmm9
            sha256msg2 xmm3, xmm6

            /* MSG1 -> W[20..23]: now MSG0 already holds W[16..19]. */
            sha256msg1 xmm4, xmm5
            movdqu xmm9, xmm3
            palignr xmm9, xmm6, 4
            paddd xmm4, xmm9
            sha256msg2 xmm4, xmm3

            /* MSG2 -> W[24..27] */
            sha256msg1 xmm5, xmm6
            movdqu xmm9, xmm4
            palignr xmm9, xmm3, 4
            paddd xmm5, xmm9
            sha256msg2 xmm5, xmm4

            /* MSG3 -> W[28..31] */
            sha256msg1 xmm6, xmm3
            movdqu xmm9, xmm5
            palignr xmm9, xmm4, 4
            paddd xmm6, xmm9
            sha256msg2 xmm6, xmm5
        .endif
        .set g, g+1
    .endr

    /* ---- Pass 2: the 64 rounds ---------------------------------------------
     * Each XFER register holds 4 words = 4 rounds = two rnds2 calls.
     * The low 64 bits are used first; pshufd 0x0E moves the high pair down.
     * ----------------------------------------------------------------------*/
    .set r, 0
    .rept 16
        movdqu xmm0, [rsp+r*16]        /* implicit K/W operand */
        sha256rnds2 xmm2, xmm1
        pshufd xmm0, xmm0, 0x0E
        sha256rnds2 xmm1, xmm2
        .set r, r+1
    .endr

    /* Feed-forward: out = in_state + working_state (mod 2^32 per word). */
    movdqu xmm8, [rsp+256]
    movdqu xmm9, [rsp+272]
    paddd xmm1, xmm8
    paddd xmm2, xmm9
.endm

/* ----------------------------------------------------------------------------
 * SHUF_STATE
 * Turn two registers holding H0..H7 in natural order into the ABEF / CDGH
 * layout that rnds2 wants. Pure register shuffling, no memory traffic.
 * --------------------------------------------------------------------------*/
.macro SHUF_STATE
    pshufd xmm1, xmm1, 0xB1
    pshufd xmm2, xmm2, 0x1B
    movdqu xmm8, xmm1
    palignr xmm8, xmm2, 8
    pblendw xmm2, xmm1, 0xF0
    movdqu xmm1, xmm8
.endm

/* Initialise state from the SHA-256 IV (start of a fresh hash). */
.macro INIT_STATE
    movdqu xmm1, [rip+IV]
    movdqu xmm2, [rip+IV+16]
    SHUF_STATE
.endm

/* Initialise state from a midstate in memory (native LE dwords).
 * This is what makes the 2-compression path possible. */
.macro INIT_STATE_MEM src
    movdqu xmm1, [\src]
    movdqu xmm2, [\src+16]
    SHUF_STATE
.endm

/* ----------------------------------------------------------------------------
 * UNSHUFFLE
 * Inverse of SHUF_STATE, plus a byte swap so the result is a standard
 * SHA-256 digest: H0..H7 written big-endian.
 * After this: xmm1 = H0..H3, xmm8 = H4..H7.
 * --------------------------------------------------------------------------*/
.macro UNSHUFFLE
    pshufd xmm1, xmm1, 0x1B
    pshufd xmm2, xmm2, 0x1B
    movdqu xmm8, xmm1
    punpckhqdq xmm8, xmm2
    punpcklqdq xmm1, xmm2
    pshufb xmm1, xmm7
    pshufb xmm8, xmm7
.endm

/* ============================================================================
 * sha256d_80 - full double SHA-256 of an 80-byte block header
 * ==========================================================================*/
.globl sha256d_80
#ifndef _WIN32
.type sha256d_80,@function
#endif
sha256d_80:
#ifdef _WIN32
    /* Win64: save callee-saved registers, then move args to the SysV layout
     * so the body below is identical on both platforms. */
    push rdi
    push rsi
    mov rdi, rcx
    mov rsi, rdx
    sub rsp, 64
    movdqu [rsp+0],xmm6
    movdqu [rsp+16],xmm7
    movdqu [rsp+32],xmm8
    movdqu [rsp+48],xmm9
#endif
    sub rsp, 440
    movdqu xmm7, [rip+SHUF_MASK]

    /* Compression 1: header[0..63]. */
    INIT_STATE
    SHA256_BLOCK rdi, 0

    /* Compression 2: header[64..79] + padding + 640-bit length.
     * Zero the whole 64-byte buffer first - uninitialised stack would
     * silently corrupt the hash. */
    pxor xmm0,xmm0
    movdqu [rsp+288],xmm0
    movdqu [rsp+304],xmm0
    movdqu [rsp+320],xmm0
    movdqu [rsp+336],xmm0
    movdqu xmm0,[rdi+64]
    movdqu [rsp+288],xmm0
    mov byte ptr [rsp+304],0x80      /* 0x80 terminator right after the data */
    mov rax,640                      /* message length in BITS = 80 * 8 */
    bswap rax                        /* length field is big-endian */
    mov [rsp+344],rax
    SHA256_BLOCK rsp,288

    /* First digest is complete. Lay it out as the message of the second hash. */
    UNSHUFFLE
    pxor xmm0,xmm0
    movdqu [rsp+352],xmm0
    movdqu [rsp+368],xmm0
    movdqu [rsp+384],xmm0
    movdqu [rsp+400],xmm0
    movdqu [rsp+352],xmm1
    movdqu [rsp+368],xmm8
    mov byte ptr [rsp+384],0x80      /* 32 bytes of data, then terminator */
    mov rax,256                      /* 32 * 8 bits */
    bswap rax
    mov [rsp+408],rax

    /* Compression 3: SHA-256 of the 32-byte first digest. Fresh IV. */
    INIT_STATE
    SHA256_BLOCK rsp,352
    UNSHUFFLE
    movdqu [rsi],xmm1
    movdqu [rsi+16],xmm8

    add rsp,440
#ifdef _WIN32
    movdqu xmm6,[rsp+0]
    movdqu xmm7,[rsp+16]
    movdqu xmm8,[rsp+32]
    movdqu xmm9,[rsp+48]
    add rsp,64
    pop rsi
    pop rdi
#endif
    ret

/* ============================================================================
 * sha256d_tail - the midstate path (hot loop of the miner)
 *
 *   mid    : state after absorbing header[0..63], native LE dwords
 *   tail   : header[64..79]; its last 4 bytes (the nonce) are ignored here
 *            because the caller rewrites them for every hash
 *   out    : final double-SHA256 digest
 *
 * Only two compressions instead of three -> ~1.5x less work per nonce.
 * ==========================================================================*/
.globl sha256d_tail
#ifndef _WIN32
.type sha256d_tail,@function
#endif
sha256d_tail:
#ifdef _WIN32
    push rdi
    push rsi
    mov rdi, rcx                     /* mid  */
    mov rsi, rdx                     /* tail */
    mov rdx, r8                      /* out  */
    sub rsp, 64
    movdqu [rsp+0],xmm6
    movdqu [rsp+16],xmm7
    movdqu [rsp+32],xmm8
    movdqu [rsp+48],xmm9
#endif
    sub rsp, 440
    movdqu xmm7, [rip+SHUF_MASK]

    /* Resume from the midstate instead of the IV - compression 1 is skipped. */
    INIT_STATE_MEM rdi

    pxor xmm0,xmm0
    movdqu [rsp+288],xmm0
    movdqu [rsp+304],xmm0
    movdqu [rsp+320],xmm0
    movdqu [rsp+336],xmm0
    movdqu xmm0,[rsi]                /* 16 bytes: merkle tail, ntime, nbits, nonce */
    movdqu [rsp+288],xmm0
    mov byte ptr [rsp+304],0x80
    mov rax,640                      /* still an 80-byte message overall */
    bswap rax
    mov [rsp+344],rax
    SHA256_BLOCK rsp,288

    UNSHUFFLE
    pxor xmm0,xmm0
    movdqu [rsp+352],xmm0
    movdqu [rsp+368],xmm0
    movdqu [rsp+384],xmm0
    movdqu [rsp+400],xmm0
    movdqu [rsp+352],xmm1
    movdqu [rsp+368],xmm8
    mov byte ptr [rsp+384],0x80
    mov rax,256
    bswap rax
    mov [rsp+408],rax
    INIT_STATE
    SHA256_BLOCK rsp,352
    UNSHUFFLE
    movdqu [rdx],xmm1
    movdqu [rdx+16],xmm8

    add rsp,440
#ifdef _WIN32
    movdqu xmm6,[rsp+0]
    movdqu xmm7,[rsp+16]
    movdqu xmm8,[rsp+32]
    movdqu xmm9,[rsp+48]
    add rsp,64
    pop rsi
    pop rdi
#endif
    ret

/* ============================================================================
 * Constants
 * On Windows the read-only section is .rdata; on ELF it is .rodata.
 * ==========================================================================*/
#ifdef _WIN32
.section .rdata
#else
.section .rodata
#endif
.align 16
/* pshufb mask: reverse the bytes inside each 32-bit dword. */
SHUF_MASK: .byte 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
.align 16
/* SHA-256 initial hash value: fractional parts of sqrt of the first 8 primes. */
IV:
    .long 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
.align 16
/* Round constants: fractional parts of cbrt of the first 64 primes. */
K256:
    .long 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
    .long 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
    .long 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
    .long 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
    .long 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
    .long 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070
    .long 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
    .long 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2