#ifndef OTMLKEM768_CLEAN_NTT_H
#define OTMLKEM768_CLEAN_NTT_H
#include "params.h"
#include <stdint.h>

extern const int16_t OTMLKEM768_CLEAN_zetas[128];

void OTMLKEM768_CLEAN_ntt(int16_t r[256]);

void OTMLKEM768_CLEAN_invntt(int16_t r[256]);

void OTMLKEM768_CLEAN_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
