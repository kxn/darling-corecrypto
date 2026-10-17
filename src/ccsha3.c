/* SHA-3 fixed-output hashes, FIPS 202, implemented for the digest ABI. */
#include <corecrypto/ccsha3.h>

static uint64_t rotate(uint64_t x, unsigned n) {
    return n ? (x << n) | (x >> (64 - n)) : x;
}

static void keccak_f1600(uint64_t a[25]) {
    static const unsigned rotation[25] = {
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
        25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
    };
    static const uint64_t rc[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL,
        0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL,
        0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL,
        0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL,
        0x0000000080000001ULL, 0x8000000080008008ULL
    };
    for (unsigned round = 0; round < 24; round++) {
        uint64_t c[5], d[5], b[25];
        for (unsigned x = 0; x < 5; x++)
            c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20];
        for (unsigned x = 0; x < 5; x++)
            d[x] = c[(x+4)%5] ^ rotate(c[(x+1)%5], 1);
        for (unsigned y = 0; y < 5; y++) for (unsigned x = 0; x < 5; x++)
            b[y + 5*((2*x+3*y)%5)] = rotate(a[x+5*y] ^ d[x], rotation[x+5*y]);
        for (unsigned y = 0; y < 5; y++) for (unsigned x = 0; x < 5; x++)
            a[x+5*y] = b[x+5*y] ^ (~b[(x+1)%5+5*y] & b[(x+2)%5+5*y]);
        a[0] ^= rc[round];
        cc_clear(sizeof(c), c); cc_clear(sizeof(d), d); cc_clear(sizeof(b), b);
    }
}

static void absorb(ccdigest_state_t state, size_t blocks, const void *input, size_t rate) {
    uint64_t *lanes = ccdigest_u64(state);
    const unsigned char *bytes = input;
    while (blocks--) {
        for (size_t i = 0; i < rate; i++)
            lanes[i/8] ^= (uint64_t)bytes[i] << (8*(i%8));
        keccak_f1600(lanes); bytes += rate;
    }
}

static void sha3_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *out) {
    unsigned char *buffer = ccdigest_data(di, ctx);
    size_t n = ccdigest_num(di, ctx);
    memset(buffer+n, 0, di->block_size-n);
    buffer[n] = 0x06; buffer[di->block_size-1] |= 0x80;
    di->compress(ccdigest_state(di, ctx), 1, buffer);
    const uint64_t *lanes = ccdigest_state_u64(di, ctx);
    /* HMAC may put its intermediate digest in this same data buffer. */
    cc_clear(di->block_size, buffer);
    for (size_t i = 0; i < di->output_size; i++) out[i] = lanes[i/8] >> (8*(i%8));
    ccdigest_num(di, ctx) = 0;
}

static const uint64_t initial_state[25] = {0};
#define SHA3(BITS, RATE, OID) \
static void sha3_##BITS##_compress(ccdigest_state_t state, size_t blocks, const void *input) { \
    absorb(state, blocks, input, RATE); \
} \
static const unsigned char sha3_##BITS##_oid[] = {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,OID}; \
static const struct ccdigest_info sha3_##BITS##_info = { \
    .output_size = BITS/8, .state_size = sizeof(initial_state), .block_size = RATE, \
    .oid_size = sizeof(sha3_##BITS##_oid), .oid = sha3_##BITS##_oid, \
    .initial_state = initial_state, .compress = sha3_##BITS##_compress, .final = sha3_final \
}; \
const struct ccdigest_info *ccsha3_##BITS##_di(void) { return &sha3_##BITS##_info; }
SHA3(224, 144, 7)
SHA3(256, 136, 8)
SHA3(384, 104, 9)
SHA3(512, 72, 10)
