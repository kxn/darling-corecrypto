#include <corecrypto/ccec25519.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cc_error.h>
#if DARLING_CORECRYPTO_BORINGSSL
#include <CCryptoBoringSSL_curve25519.h>
#endif

int cccurve25519(ccec25519key shared_secret, ccec25519secretkey private_key, ccec25519pubkey public_key) {
    if (!shared_secret || !private_key || !public_key) return CCERR_PARAMETER;
#if DARLING_CORECRYPTO_BORINGSSL
    if (X25519(shared_secret, private_key, public_key)) return CCERR_OK;
    cc_clear(32, shared_secret); return CCERR_INTEGRITY;
#else
    return CCERR_CRYPTO_CONFIG;
#endif
};

int cccurve25519_make_key_pair(struct ccrng_state* rng, ccec25519pubkey public_key, ccec25519secretkey private_key) {
    if (!public_key || !private_key) return CCERR_PARAMETER;
    int status = cccurve25519_make_priv(rng, private_key);
    if (!status) status = cccurve25519_make_pub(public_key, private_key);
    if (status) { cc_clear(32, private_key); cc_clear(32, public_key); }
    return status;
};

int cccurve25519_make_priv(struct ccrng_state *rng, ccec25519secretkey sk) {
    if (!rng || !rng->generate || !sk) return CCERR_PARAMETER;
    int status = ccrng_generate(rng, 32, sk);
    if (status) { cc_clear(32, sk); return status; }
    sk[0] &= 248; sk[31] = (sk[31] & 127) | 64;
    return CCERR_OK;
}

int cccurve25519_make_pub(ccec25519pubkey pk, const ccec25519secretkey sk) {
    if (!pk || !sk) return CCERR_PARAMETER;
#if DARLING_CORECRYPTO_BORINGSSL
    X25519_public_from_private(pk, sk); return CCERR_OK;
#else
    return CCERR_CRYPTO_CONFIG;
#endif
}

/* This backend uses BoringSSL's constant-time ladder, without randomized
 * coordinate blinding. The RNG parameter is needed only for key generation. */
int cccurve25519_make_pub_with_rng(struct ccrng_state *rng, ccec25519pubkey pk, const ccec25519secretkey sk) {
    if (!rng || !rng->generate) return CCERR_PARAMETER;
    return cccurve25519_make_pub(pk, sk);
}
int cccurve25519_with_rng(struct ccrng_state *rng, ccec25519key out, const ccec25519secretkey sk, const ccec25519base base) {
    if (!rng || !rng->generate) return CCERR_PARAMETER;
    return cccurve25519(out, (unsigned char *)sk, (unsigned char *)base);
}

/* Ed25519 here supports the SHA-512 descriptor supplied by this library.
 * Refuse other digests rather than silently substituting a different hash. */
int cced25519_make_pub(const struct ccdigest_info *di, ccec25519pubkey pk, const ccec25519secretkey sk) {
    if (di != ccsha512_di() || !pk || !sk) return CCERR_PARAMETER;
#if DARLING_CORECRYPTO_BORINGSSL
    unsigned char expanded[64]; ED25519_keypair_from_seed(pk, expanded, sk);
    cc_clear(sizeof(expanded), expanded); return CCERR_OK;
#else
    return CCERR_CRYPTO_CONFIG;
#endif
}
int cced25519_make_key_pair(const struct ccdigest_info *di, struct ccrng_state *rng, ccec25519pubkey pk, ccec25519secretkey sk) {
    if (di != ccsha512_di() || !rng || !rng->generate || !pk || !sk) return CCERR_PARAMETER;
    int status = ccrng_generate(rng, 32, sk);
    if (!status) status = cced25519_make_pub(di, pk, sk);
    if (status) { cc_clear(32, sk); cc_clear(32, pk); }
    return status;
}
int cced25519_sign(const struct ccdigest_info *di, ccec25519signature sig, size_t len, const void *msg, const ccec25519pubkey pk, const ccec25519secretkey sk) {
    if (di != ccsha512_di() || !sig || (len && !msg) || !pk || !sk) return CCERR_PARAMETER;
#if DARLING_CORECRYPTO_BORINGSSL
    unsigned char derived[32], expanded[64];
    ED25519_keypair_from_seed(derived, expanded, sk);
    int status = cc_cmp_safe(32, derived, pk) ? CCERR_PARAMETER :
        (ED25519_sign(sig, msg, len, expanded) ? CCERR_OK : CCERR_INTERNAL);
    cc_clear(sizeof(expanded), expanded); cc_clear(sizeof(derived), derived);
    if (status) cc_clear(64, sig);
    return status;
#else
    return CCERR_CRYPTO_CONFIG;
#endif
}
int cced25519_verify(const struct ccdigest_info *di, size_t len, const void *msg, const ccec25519signature sig, const ccec25519pubkey pk) {
    if (di != ccsha512_di() || (len && !msg) || !sig || !pk) return CCERR_PARAMETER;
#if DARLING_CORECRYPTO_BORINGSSL
    return ED25519_verify(msg, len, sig, pk) ? CCERR_OK : CCERR_INTEGRITY;
#else
    return CCERR_CRYPTO_CONFIG;
#endif
}
