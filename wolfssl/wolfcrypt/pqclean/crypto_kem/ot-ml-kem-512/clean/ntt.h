#ifndef OTMLKEM512_CLEAN_NTT_H
#define OTMLKEM512_CLEAN_NTT_H

#include "params.h"
#include <stdint.h>

extern const int16_t OTMLKEM512_CLEAN_zetas[128];

void OTMLKEM512_CLEAN_ntt(int16_t r[256]);

void OTMLKEM512_CLEAN_invntt(int16_t r[256]);

void OTMLKEM512_CLEAN_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
