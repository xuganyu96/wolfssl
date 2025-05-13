#ifndef OTMLKEM768_CLEAN_CBD_H
#define OTMLKEM768_CLEAN_CBD_H

#include <stdint.h>

#include "params.h"
#include "poly.h"

void OTMLKEM768_CLEAN_poly_cbd_eta1(poly *r, const uint8_t buf[KYBER_ETA1 * KYBER_N / 4]);

void OTMLKEM768_CLEAN_poly_cbd_eta2(poly *r, const uint8_t buf[KYBER_ETA2 * KYBER_N / 4]);

#endif
