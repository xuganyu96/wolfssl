#ifndef OTMLKEM1024_CLEAN_POLYVEC_H
#define OTMLKEM1024_CLEAN_POLYVEC_H
#include "params.h"
#include "poly.h"
#include <stdint.h>

typedef struct {
    poly vec[KYBER_K];
} polyvec;

void OTMLKEM1024_CLEAN_polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a);
void OTMLKEM1024_CLEAN_polyvec_decompress(polyvec *r,
                                          const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES]);

void OTMLKEM1024_CLEAN_polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a);
void OTMLKEM1024_CLEAN_polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES]);

void OTMLKEM1024_CLEAN_polyvec_ntt(polyvec *r);
void OTMLKEM1024_CLEAN_polyvec_invntt_tomont(polyvec *r);

void OTMLKEM1024_CLEAN_polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);

void OTMLKEM1024_CLEAN_polyvec_reduce(polyvec *r);

void OTMLKEM1024_CLEAN_polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif
