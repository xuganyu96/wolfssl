#ifndef OTMLKEM1024_CLEAN_NTT_H
#define OTMLKEM1024_CLEAN_NTT_H
#include "params.h"
#include <stdint.h>

extern const int16_t OTMLKEM1024_CLEAN_zetas[128];

void OTMLKEM1024_CLEAN_ntt(int16_t r[256]);

void OTMLKEM1024_CLEAN_invntt(int16_t r[256]);

void OTMLKEM1024_CLEAN_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
