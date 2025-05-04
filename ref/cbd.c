#include <stdint.h>
#include "params.h"
#include "cbd.h"


void cbd1(poly *r, const uint8_t buf[KYBER_N / 4]);
void cbd2(poly *r, const uint8_t buf[2*KYBER_N / 4]);
void cbd3(poly *r, const uint8_t buf[3*KYBER_N / 4]);
void cbd4(poly *r, const uint8_t buf[4*KYBER_N / 4]);
void cbd5(poly *r, const uint8_t buf[5*KYBER_N / 4]);
void cbd6(poly *r, const uint8_t buf[6*KYBER_N / 4]);
void cbd7(poly *r, const uint8_t buf[7*KYBER_N / 4]);
void cbd10(poly *r, const uint8_t buf[10*KYBER_N / 4]);

/*************************************************
* Name:        load32_littleendian
*
* Description: load 4 bytes into a 32-bit integer
*              in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x
**************************************************/
static uint32_t load32_littleendian(const uint8_t x[4])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  r |= (uint32_t)x[3] << 24;
  return r;
}

/*************************************************
* Name:        load24_littleendian
*
* Description: load 3 bytes into a 32-bit integer
*              in little-endian order.
*              This function is only needed for Kyber-512
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
**************************************************/
static uint32_t load24_littleendian(const uint8_t x[3])
{
  uint32_t r;
  r  = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  return r;
}



void cbd1(poly *r, const uint8_t buf[KYBER_N / 4]) {
  unsigned int i, j;
  uint8_t t, d;
  int16_t a, b;

  for (i = 0; i < KYBER_N / 4; i++) {
    t = buf[i];
    d = t & 0x11;
    d += (t >> 1) & 0x11;

    d += (t >> 2) & 0x11;
    d += (t >> 3) & 0x11;

    for (j = 0; j < 4; j++) {
      a = (d >> (2 * j + 0)) & 0x1;
      b = (d >> (2 * j + 1)) & 0x1;
      r->coeffs[4 * i + j] = a - b;
    }
  }
}



/*************************************************
* Name:        cbd2
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=2
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
void cbd2(poly *r, const uint8_t buf[2*KYBER_N/4])
{
  unsigned int i,j;
  uint32_t t,d;
  int16_t a,b;

  for(i=0;i<KYBER_N/8;i++) {
    t  = load32_littleendian(buf+4*i);
    d  = t & 0x55555555;
    d += (t>>1) & 0x55555555;

    for(j=0;j<8;j++) {
      a = (d >> (4*j+0)) & 0x3;
      b = (d >> (4*j+2)) & 0x3;
      r->coeffs[8*i+j] = a - b;
    }
  }
}

/*************************************************
* Name:        cbd3
*
* Description: Given an array of uniformly random bytes, compute
*              polynomial with coefficients distributed according to
*              a centered binomial distribution with parameter eta=3.
*              This function is only needed for Kyber-512
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *buf: pointer to input byte array
**************************************************/
void cbd3(poly *r, const uint8_t buf[3*KYBER_N/4])
{
  unsigned int i,j;
  uint32_t t,d;
  int16_t a,b;

  for(i=0;i<KYBER_N/4;i++) {
    t  = load24_littleendian(buf+3*i);
    d  = t & 0x00249249;
    d += (t>>1) & 0x00249249;
    d += (t>>2) & 0x00249249;

    for(j=0;j<4;j++) {
      a = (d >> (6*j+0)) & 0x7;
      b = (d >> (6*j+3)) & 0x7;
      r->coeffs[4*i+j] = a - b;
    }
  }
}



void cbd4(poly *r, const uint8_t buf[4 * KYBER_N / 4]) {
  unsigned int i, j;
  uint32_t t, d;
  int16_t a, b;

  for (i = 0; i < KYBER_N / 4; i++) {
    t = buf[4 * i + 0];
    t |= ((uint32_t)buf[4 * i + 1]) << 8;
    t |= ((uint32_t)buf[4 * i + 2]) << 16;
    t |= ((uint32_t)buf[4 * i + 3]) << 24;

    d = t & 0x11111111;
    d += (t >> 1) & 0x11111111;
    d += (t >> 2) & 0x11111111;
    d += (t >> 3) & 0x11111111;

    for (j = 0; j < 4; j++) {
      a = (d >> (8 * j + 0)) & 0xF;
      b = (d >> (8 * j + 4)) & 0xF;
      r->coeffs[4 * i + j] = a - b;
    }
  }
}


void cbd5(poly *r, const uint8_t buf[5 * KYBER_N / 4]) {
  unsigned int i, j;
  uint64_t t, d;
  int16_t a, b;

  for (i = 0; i < KYBER_N / 4; i++) {
    t  = buf[5 * i + 0];
    t |= ((uint64_t)buf[5 * i + 1]) << 8;
    t |= ((uint64_t)buf[5 * i + 2]) << 16;
    t |= ((uint64_t)buf[5 * i + 3]) << 24;
    t |= ((uint64_t)buf[5 * i + 4]) << 32;

    d = t & 0x0842108421ULL;
    d += (t >> 1) & 0x0842108421ULL;
    d += (t >> 2) & 0x0842108421ULL;
    d += (t >> 3) & 0x0842108421ULL;
    d += (t >> 4) & 0x0842108421ULL;

    for (j = 0; j < 4; j++) {
      a = (d >> (10 * j + 0)) & 0x1F;
      b = (d >> (10 * j + 5)) & 0x1F;
      r->coeffs[4 * i + j] = a - b;
    }
  }
}



void cbd6(poly *r, const uint8_t buf[6 * KYBER_N / 4]) {
  unsigned int i, j;
  uint64_t t, d;
  int16_t a, b;

  for (i = 0; i < KYBER_N / 4; i++) {
    t  = buf[6 * i + 0];
    t |= ((uint64_t)buf[6 * i + 1]) << 8;
    t |= ((uint64_t)buf[6 * i + 2]) << 16;
    t |= ((uint64_t)buf[6 * i + 3]) << 24;
    t |= ((uint64_t)buf[6 * i + 4]) << 32;
    t |= ((uint64_t)buf[6 * i + 5]) << 40;

    d = t & 0x210842108421ULL;
    d += (t >> 1) & 0x210842108421ULL;
    d += (t >> 2) & 0x210842108421ULL;
    d += (t >> 3) & 0x210842108421ULL;
    d += (t >> 4) & 0x210842108421ULL;
    d += (t >> 5) & 0x210842108421ULL;

    for (j = 0; j < 4; j++) {
      a = (d >> (12 * j + 0)) & 0x3F;
      b = (d >> (12 * j + 6)) & 0x3F;
      r->coeffs[4 * i + j] = a - b;
    }
  }
}


void cbd7(poly *r, const uint8_t buf[7 * KYBER_N / 4]) {
  unsigned int i, j;
  uint64_t t, d;
  int16_t a, b;

  for (i = 0; i < KYBER_N / 4; i++) {
    t  = buf[7 * i + 0];
    t |= ((uint64_t)buf[7 * i + 1]) << 8;
    t |= ((uint64_t)buf[7 * i + 2]) << 16;
    t |= ((uint64_t)buf[7 * i + 3]) << 24;
    t |= ((uint64_t)buf[7 * i + 4]) << 32;
    t |= ((uint64_t)buf[7 * i + 5]) << 40;
    t |= ((uint64_t)buf[7 * i + 6]) << 48;

    d = t & 0x4210842108421ULL;
    d += (t >> 1) & 0x4210842108421ULL;
    d += (t >> 2) & 0x4210842108421ULL;
    d += (t >> 3) & 0x4210842108421ULL;
    d += (t >> 4) & 0x4210842108421ULL;
    d += (t >> 5) & 0x4210842108421ULL;
    d += (t >> 6) & 0x4210842108421ULL;

    for (j = 0; j < 4; j++) {
      a = (d >> (14 * j + 0)) & 0x7F;
      b = (d >> (14 * j + 7)) & 0x7F;
      r->coeffs[4 * i + j] = a - b;
    }
  }
}

void cbd10(poly *r, const uint8_t buf[10 * KYBER_N / 4]) {
  unsigned int i, j;
  __uint128_t t, d;
  int16_t a, b;

  for (i = 0; i < KYBER_N / 4; i++) {
    t = 0;
    for (j = 0; j < 10; j++) {
      t |= (__uint128_t)buf[10 * i + j] << (8 * j);
    }

    d  = t & 0x00041041041041041ULL;
    d += (t >> 1) & 0x00041041041041041ULL;
    d += (t >> 2) & 0x00041041041041041ULL;
    d += (t >> 3) & 0x00041041041041041ULL;
    d += (t >> 4) & 0x00041041041041041ULL;
    d += (t >> 5) & 0x00041041041041041ULL;
    d += (t >> 6) & 0x00041041041041041ULL;
    d += (t >> 7) & 0x00041041041041041ULL;
    d += (t >> 8) & 0x00041041041041041ULL;
    d += (t >> 9) & 0x00041041041041041ULL;

    for (j = 0; j < 4; j++) {
      a = (d >> (20 * j + 0)) & 0x3FF;
      b = (d >> (20 * j + 10)) & 0x3FF;
      r->coeffs[4 * i + j] = a - b;
    }
  }
}




void poly_cbd_eta1(poly *r, const uint8_t buf[KYBER_ETA1*KYBER_N/4])
{
  #if KYBER_ETA1 == 1
    cbd1(r, buf);
  #elif KYBER_ETA1 == 2
    cbd2(r, buf);
  #elif KYBER_ETA1 == 3
    cbd3(r, buf);
  #elif KYBER_ETA1 == 4
    cbd4(r, buf);
  #elif KYBER_ETA1 == 5
    cbd5(r, buf);
  #elif KYBER_ETA1 == 6
    cbd6(r, buf);
  #elif KYBER_ETA1 == 7
    cbd7(r, buf);  
  #elif KYBER_ETA1 == 10
    cbd10(r, buf);
  #else
  #error "This implementation requires eta1 in {1,2,3,4,5,6,7}"
  #endif
}

void poly_cbd_eta2(poly *r, const uint8_t buf[KYBER_ETA2*KYBER_N/4])
{
  #if KYBER_ETA2 == 1
    cbd1(r, buf);
  #elif KYBER_ETA2 == 2
    cbd2(r, buf);
  #elif KYBER_ETA2 == 3
    cbd3(r, buf);
  #elif KYBER_ETA2 == 4
    cbd4(r, buf);
  #elif KYBER_ETA2 == 5
    cbd5(r, buf);
  #elif KYBER_ETA2 == 6
    cbd6(r, buf);
  #elif KYBER_ETA2 == 7
    cbd7(r, buf);  
  #elif KYBER_ETA1 == 10
    cbd10(r, buf);
  #else
  #error "This implementation requires eta1 in {1,2,3,4,5,6,7}"
  #endif
}
