/*
 * TweetNaCl - A self-contained public-domain crypto library
 * https://tweetnacl.cr.yp.to/
 *
 * This is a minimal implementation of NaCl that fits in 100 tweets.
 * Public domain.
 */

#ifndef TWEETNACL_H
#define TWEETNACL_H

#ifdef __cplusplus
extern "C" {
#endif

#define crypto_sign_BYTES 64
#define crypto_sign_PUBLICKEYBYTES 32
#define crypto_sign_SECRETKEYBYTES 64

int crypto_sign_keypair(unsigned char* pk, unsigned char* sk);
int crypto_sign(unsigned char* sm, unsigned long long* smlen,
                const unsigned char* m, unsigned long long mlen,
                const unsigned char* sk);
int crypto_sign_open(unsigned char* m, unsigned long long* mlen,
                     const unsigned char* sm, unsigned long long smlen,
                     const unsigned char* pk);

/* Ed25519 detached signature functions */
int crypto_sign_detached(unsigned char* sig,
                         const unsigned char* m, unsigned long long mlen,
                         const unsigned char* sk);
int crypto_sign_verify_detached(const unsigned char* sig,
                                const unsigned char* m, unsigned long long mlen,
                                const unsigned char* pk);

/* Hash function (SHA-512) */
#define crypto_hash_BYTES 64
int crypto_hash(unsigned char* out, const unsigned char* m, unsigned long long n);

/* Random bytes */
void randombytes(unsigned char* x, unsigned long long xlen);

#ifdef __cplusplus
}
#endif

#endif /* TWEETNACL_H */
