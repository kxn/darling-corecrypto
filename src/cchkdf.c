#include <corecrypto/cchkdf.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/cc_error.h>

/* RFC 5869, using the caller's digest implementation. */
static int hkdf_valid_digest(const struct ccdigest_info *di) {
    return di && di->output_size && di->output_size <= di->block_size &&
        di->block_size <= 1024 && di->state_size <= 1024 &&
        di->initial_state && di->compress && di->final;
}

int cchkdf(const struct ccdigest_info *di, size_t ikmLen, const void *ikm,
	size_t saltLen, const void *salt, size_t infoLen, const void *info,
	size_t dkLen, void *dk) {
    if (!hkdf_valid_digest(di) || (ikmLen && !ikm) || (saltLen && !salt) ||
        (infoLen && !info) || (dkLen && !dk) || dkLen > 255 * di->output_size)
        return CCERR_PARAMETER;
    unsigned char prk[di->output_size];
    int result = cchkdf_extract(di, saltLen, salt, ikmLen, ikm, prk);
    if (!result) result = cchkdf_expand(di, sizeof(prk), prk, infoLen, info, dkLen, dk);
    cc_clear(sizeof(prk), prk);
    return result;
}

int cchkdf_extract(const struct ccdigest_info *di, size_t saltLen, const void *salt,
	size_t keyDerivationKeyLen, const void *keyDerivationKey, void *prk) {
    if (!hkdf_valid_digest(di) || !prk || (saltLen && !salt) ||
        (keyDerivationKeyLen && !keyDerivationKey)) return CCERR_PARAMETER;
    /* Empty HMAC key and HashLen zero bytes have identical padded values. */
    cchmac(di, saltLen, salt, keyDerivationKeyLen, keyDerivationKey, prk);
    return CCERR_OK;
}

int cchkdf_expand(const struct ccdigest_info *di, size_t prkLen, const void *prk,
	size_t contextLen, const void *context, size_t derivedKeyLen, void *derivedKey) {
    if (!hkdf_valid_digest(di) || (prkLen && !prk) || (contextLen && !context) ||
        (derivedKeyLen && !derivedKey) || derivedKeyLen > 255 * di->output_size)
        return CCERR_PARAMETER;
    unsigned char previous[di->output_size];
    unsigned char *output = derivedKey;
    size_t previousLen = 0, remaining = derivedKeyLen;
    for (unsigned counter = 1; remaining; counter++) {
        unsigned char octet = counter;
        cchmac_di_decl(di, ctx);
        cchmac_init(di, ctx, prkLen, prk);
        if (previousLen) cchmac_update(di, ctx, previousLen, previous);
        if (contextLen) cchmac_update(di, ctx, contextLen, context);
        cchmac_update(di, ctx, 1, &octet);
        cchmac_final(di, ctx, previous);
        cchmac_di_clear(di, ctx);
        previousLen = di->output_size;
        size_t n = remaining < previousLen ? remaining : previousLen;
        memcpy(output, previous, n);
        output += n; remaining -= n;
    }
    cc_clear(sizeof(previous), previous);
    return CCERR_OK;
}
