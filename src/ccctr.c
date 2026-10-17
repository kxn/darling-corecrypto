#include <corecrypto/ccmode_factory.h>
#include <corecrypto/cc_error.h>

/* Opaque context: header, counter, unused keystream, aligned ECB key. */
static unsigned char *ctr_counter(struct _ccmode_ctr_key *key) {
    return (unsigned char *)key->u;
}
static unsigned char *ctr_pad(struct _ccmode_ctr_key *key) {
    return ctr_counter(key) + ccn_sizeof_size(key->ecb->block_size);
}
static ccecb_ctx *ctr_ecb_key(struct _ccmode_ctr_key *key) {
    return (ccecb_ctx *)(ctr_pad(key) + ccn_sizeof_size(key->ecb->block_size));
}

int ccmode_ctr_init(const struct ccmode_ctr* ctr, ccctr_ctx* _ctx, size_t rawkey_len, const void* rawkey, const void* iv) {
    if (!ctr || !_ctx || !rawkey || !iv || !ctr->custom) return CCERR_PARAMETER;
    const struct ccmode_ecb *ecb = ctr->custom;
    if (!ecb->block_size || !ecb->init || !ecb->ecb) return CCERR_PARAMETER;
    struct _ccmode_ctr_key *key = (void *)_ctx;
    key->ecb = ecb;
    int status = ecb->init(ecb, ctr_ecb_key(key), rawkey_len, rawkey);
    if (status) { cc_clear(ctr->size, _ctx); return status; }
    return ccmode_ctr_setctr(ctr, _ctx, iv);
};

int ccmode_ctr_crypt(ccctr_ctx* ctx, size_t nbytes, const void* in, void* out) {
    if (!ctx || (nbytes && (!in || !out))) return CCERR_PARAMETER;
    struct _ccmode_ctr_key *key = (void *)ctx;
    const struct ccmode_ecb *ecb = key->ecb;
    if (!ecb || !ecb->block_size || key->pad_len > ecb->block_size) return CCERR_PARAMETER;
    const unsigned char *src = in; unsigned char *dst = out;
    unsigned char *counter = ctr_counter(key), *pad = ctr_pad(key);
    while (nbytes) {
        if (!key->pad_len) {
            int status = ecb->ecb(ctr_ecb_key(key), 1, counter, pad);
            if (status) return status;
            /* Apple CTR uses a big-endian counter of at most 64 bits. */
            size_t width = ecb->block_size < 8 ? ecb->block_size : 8;
            for (size_t i = 0; i < width; i++)
                if (++counter[ecb->block_size - 1 - i]) break;
            key->pad_len = ecb->block_size;
        }
        size_t n = nbytes < key->pad_len ? nbytes : key->pad_len;
        size_t offset = ecb->block_size - key->pad_len;
        for (size_t i = 0; i < n; i++) dst[i] = src[i] ^ pad[offset + i];
        key->pad_len -= n; nbytes -= n; src += n; dst += n;
    }
    return CCERR_OK;
};

int ccmode_ctr_setctr(const struct ccmode_ctr* ctr, ccctr_ctx* ctx, const void* iv) {
    if (!ctr || !ctx || !iv) return CCERR_PARAMETER;
    struct _ccmode_ctr_key *key = (void *)ctx;
    if (!key->ecb || key->ecb != ctr->custom) return CCERR_PARAMETER;
    memcpy(ctr_counter(key), iv, key->ecb->block_size);
    cc_clear(key->ecb->block_size, ctr_pad(key));
    key->pad_len = 0;
    return CCERR_OK;
};
