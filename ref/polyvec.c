#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"

/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_compress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a)
{
  unsigned int i,j,k;
  uint64_t d0;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  uint16_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      for(k=0;k<8;k++) {
        t[k]  = a->vec[i].coeffs[8*j+k];
        t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
/*      t[k]  = ((((uint32_t)t[k] << 11) + KYBER_Q/2)/KYBER_Q) & 0x7ff; */
        d0 = t[k];
        d0 <<= 11;
        d0 += 1664;
        d0 *= 645084;
        d0 >>= 31;
        t[k] = d0 & 0x7ff;
      }

      r[ 0] = (t[0] >>  0);
      r[ 1] = (t[0] >>  8) | (t[1] << 3);
      r[ 2] = (t[1] >>  5) | (t[2] << 6);
      r[ 3] = (t[2] >>  2);
      r[ 4] = (t[2] >> 10) | (t[3] << 1);
      r[ 5] = (t[3] >>  7) | (t[4] << 4);
      r[ 6] = (t[4] >>  4) | (t[5] << 7);
      r[ 7] = (t[5] >>  1);
      r[ 8] = (t[5] >>  9) | (t[6] << 2);
      r[ 9] = (t[6] >>  6) | (t[7] << 5);
      r[10] = (t[7] >>  3);
      r += 11;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
  uint16_t t[4];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {
      for(k=0;k<4;k++) {
        t[k]  = a->vec[i].coeffs[4*j+k];
        t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
/*      t[k]  = ((((uint32_t)t[k] << 10) + KYBER_Q/2)/ KYBER_Q) & 0x3ff; */
        d0 = t[k];
        d0 <<= 10;
        d0 += 1665;
        d0 *= 1290167;
        d0 >>= 32;
        t[k] = d0 & 0x3ff;
      }

      r[0] = (t[0] >> 0);
      r[1] = (t[0] >> 8) | (t[1] << 2);
      r[2] = (t[1] >> 6) | (t[2] << 4);
      r[3] = (t[2] >> 4) | (t[3] << 6);
      r[4] = (t[3] >> 2);
      r += 5;
    }
  }
  #elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 288))
  uint16_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      for(k=0;k<8;k++) {
        t[k]  = a->vec[i].coeffs[8*j+k];
        t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
        d0 = t[k];
        d0 <<= 9; 
        d0 += 1664;
        d0 *= 2580333;
        d0 >>= 33;
        t[k] = d0 & 0x1ff;
      }

      r[ 0] = (t[0] >>  0);
      r[ 1] = (t[0] >>  8) | (t[1] << 1);
      r[ 2] = (t[1] >>  7) | (t[2] << 2);
      r[ 3] = (t[2] >>  6) | (t[3] << 3);
      r[ 4] = (t[3] >>  5) | (t[4] << 4);
      r[ 5] = (t[4] >>  4) | (t[5] << 5);
      r[ 6] = (t[5] >>  3) | (t[6] << 6);
      r[ 7] = (t[6] >>  2) | (t[7] << 7);
      r[ 8] = (t[7] >>  1);
      r += 9;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 256))
  uint8_t t[4];
  int16_t u;
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {
      for(k=0;k<4;k++) {
        u  = a->vec[i].coeffs[4*j+k];
        u += (u >> 15) & KYBER_Q;
        d0 = u << 8;
        d0 += 1665;
        d0 *= 5040;
        d0 >>= 24; 
        t[k] = d0 & 0xff; 
      }
      
      r[0] = t[0];
      r[1] = t[1];
      r[2] = t[2];
      r[3] = t[3];
      r += 4;

    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 224))
  uint8_t t [8];
  int16_t u;
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      for(k=0;k<8;k++) {
        u  = a->vec[i].coeffs[8*j+k];
        u += (u >> 15) & KYBER_Q;
        d0 = u << 7;
        d0 += 1664;
        d0 *= 10080; 
        d0 >>= 25; 
        t[k] = d0 & 0x7f;
      }

      r[ 0] = (t[0] >> 0) | (t[1] << 7);
      r[ 1] = (t[1] >> 1) | (t[2] << 6);
      r[ 2] = (t[2] >> 2) | (t[3] << 5);
      r[ 3] = (t[3] >> 3) | (t[4] << 4);
      r[ 4] = (t[4] >> 4) | (t[5] << 3);
      r[ 5] = (t[5] >> 5) | (t[6] << 2);
      r[ 6] = (t[6] >> 6) | (t[7] << 1);
      r += 7;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 192))
  uint8_t t[4];
  int16_t u;
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {
      for(k=0;k<4;k++) {
        u  = a->vec[i].coeffs[4*j+k];
        u += (u >> 15) & KYBER_Q;
        d0 = u << 6;
        d0 += 1665;
        d0 *= 20159; 
        d0 >>= 26; 
        t[k] = d0 & 0x3f; 
      }

      r[0] = (t[0] >> 0) | (t[1] << 6);
      r[1] = (t[1] >> 2) | (t[2] << 4);
      r[2] = (t[2] >> 4) | (t[3] << 2);
      r += 3;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 160))
  uint8_t t[8];
  int16_t u;
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      for(k=0;k<8;k++) {
        u  = a->vec[i].coeffs[8*j+k];
        u += (u >> 15) & KYBER_Q;
        d0 = u << 5;
        d0 += 1664;
        d0 *= 40318; 
        d0 >>= 27; 
        t[k] = d0 & 0x1f; 
      }

      r[0] = (t[0] >> 0) | (t[1] << 5);
      r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
      r[2] = (t[3] >> 1) | (t[4] << 4);
      r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
      r[4] = (t[6] >> 2) | (t[7] << 3);
      r += 5;
    }
  }

#else
#error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K, 288*KYBER_K, 256*KYBER_K, 224*KYBER_K, 192*KYBER_K, 160*KYBER_K, 128*KYBER_K}"
#endif
}

/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress
*
* Arguments:   - polyvec *r:       pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYVECCOMPRESSEDBYTES)
**************************************************/
void polyvec_decompress(polyvec *r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES])
{
  unsigned int i,j,k;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  uint16_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      t[0] = (a[0] >> 0) | ((uint16_t)a[ 1] << 8);
      t[1] = (a[1] >> 3) | ((uint16_t)a[ 2] << 5);
      t[2] = (a[2] >> 6) | ((uint16_t)a[ 3] << 2) | ((uint16_t)a[4] << 10);
      t[3] = (a[4] >> 1) | ((uint16_t)a[ 5] << 7);
      t[4] = (a[5] >> 4) | ((uint16_t)a[ 6] << 4);
      t[5] = (a[6] >> 7) | ((uint16_t)a[ 7] << 1) | ((uint16_t)a[8] << 9);
      t[6] = (a[8] >> 2) | ((uint16_t)a[ 9] << 6);
      t[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
      a += 11;

      for(k=0;k<8;k++)
        r->vec[i].coeffs[8*j+k] = ((uint32_t)(t[k] & 0x7FF)*KYBER_Q + 1024) >> 11;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
  uint16_t t[4];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {
      t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
      t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
      t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
      t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
      a += 5;

      for(k=0;k<4;k++)
        r->vec[i].coeffs[4*j+k] = ((uint32_t)(t[k] & 0x3FF)*KYBER_Q + 512) >> 10;
    }
  }
  #elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 288))
  uint16_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
      t[1] = (a[1] >> 1) | ((uint16_t)a[2] << 7);
      t[2] = (a[2] >> 2) | ((uint16_t)a[3] << 6);
      t[3] = (a[3] >> 3) | ((uint16_t)a[4] << 5);
      t[4] = (a[4] >> 4) | ((uint16_t)a[5] << 4);
      t[5] = (a[5] >> 5) | ((uint16_t)a[6] << 3);
      t[6] = (a[6] >> 6) | ((uint16_t)a[7] << 2);
      t[7] = (a[7] >> 7) | ((uint16_t)a[8] << 1);
      a += 9;

      for(k=0;k<8;k++)
        r->vec[i].coeffs[8*j+k] = ((uint32_t)(t[k] & 0x1FF)*KYBER_Q + 256) >> 9;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 256))
  uint8_t t[4];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {
      t[0] = a[0];
      t[1] = a[1];
      t[2] = a[2];
      t[3] = a[3];
      a += 4;

      for(k=0;k<4;k++)
        r->vec[i].coeffs[4*j+k] = ((uint32_t)(t[k] & 0xFF)*KYBER_Q + 128) >> 8;
    }
  }

#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 224))
  uint8_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {
      t[0] = (a[0] >> 0);
      t[1] = (a[0] >> 7) | (a[1] << 1);
      t[2] = (a[1] >> 6) | (a[2] << 2);
      t[3] = (a[2] >> 5) | (a[3] << 3);
      t[4] = (a[3] >> 4) | (a[4] << 4);
      t[5] = (a[4] >> 3) | (a[5] << 5);
      t[6] = (a[5] >> 2) | (a[6] << 6);
      t[7] = (a[6] >> 1);
      a += 7;


      for(k=0;k<8;k++)
        r->vec[i].coeffs[8*j+k] = ((uint32_t)(t[k] & 0x7F)*KYBER_Q + 64) >> 7;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 192))
  uint8_t t[4];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/4;j++) {

      t[0] = a[0];
      t[1] = (a[0] >> 6) | (a[1] << 2);
      t[2] = (a[1] >> 4) | (a[2] << 4);
      t[3] = (a[2] >> 2);
      a += 3;

      for(k=0;k<4;k++)
        r->vec[i].coeffs[4*j+k] = ((uint32_t)(t[k] & 0x3F)*KYBER_Q + 32) >> 6;
    }
  }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 160))
  uint8_t t[8];
  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_N/8;j++) {

      t[0] = (a[0] >> 0);
      t[1] = (a[0] >> 5) | (a[1] << 3);
      t[2] = (a[1] >> 2);
      t[3] = (a[1] >> 7) | (a[2] << 1);
      t[4] = (a[2] >> 4) | (a[3] << 4);
      t[5] = (a[3] >> 1);
      t[6] = (a[3] >> 6) | (a[4] << 2);
      t[7] = (a[4] >> 3);
      a += 5;

      for(k=0;k<8;k++)
        r->vec[i].coeffs[8*j+k] = ((uint32_t)(t[k] & 0x1F)*KYBER_Q + 16) >> 5;
    }
  }
#else
#error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K, 288*KYBER_K, 256*KYBER_K, 224*KYBER_K, 192*KYBER_K, 160*KYBER_K, 128*KYBER_K}"
#endif
}

/*************************************************
* Name:        polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for KYBER_POLYVECBYTES)
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_tobytes(uint8_t r[KYBER_POLYVECBYTES], const polyvec *a)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_tobytes(r+i*KYBER_POLYBYTES, &a->vec[i]);
}

/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes
*
* Arguments:   - uint8_t *r:       pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
*                                  (of length KYBER_POLYVECBYTES)
**************************************************/
void polyvec_frombytes(polyvec *r, const uint8_t a[KYBER_POLYVECBYTES])
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_frombytes(&r->vec[i], a+i*KYBER_POLYBYTES);
}

/*************************************************
* Name:        polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_ntt(polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_ntt(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_invntt_tomont
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_invntt_tomont(polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_invntt_tomont(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_basemul_acc_montgomery
*
* Description: Multiply elements of a and b in NTT domain, accumulate into r,
*              and multiply by 2^-16.
*
* Arguments: - poly *r: pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b)
{
  unsigned int i;
  poly t;

  poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
  for(i=1;i<KYBER_K;i++) {
    poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
    poly_add(r, r, &t);
  }

  poly_reduce(r);
}

/*************************************************
* Name:        polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials;
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - polyvec *r: pointer to input/output polynomial
**************************************************/
void polyvec_reduce(polyvec *r)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_reduce(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r: pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
  unsigned int i;
  for(i=0;i<KYBER_K;i++)
    poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}
