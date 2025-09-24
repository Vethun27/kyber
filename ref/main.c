#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "kem.h"
#include "randombytes.h"
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "cpucycles.h"
#include "speed_print.h"
#include "time.h"
#include "symmetric.h"


#include <windows.h>


#if (SPEED == 0)
#define NTESTS 1000

int test_keys(void);
int test_invalid_sk_a(void);
int test_invalid_ciphertext(void);

int test_invalid_ciphertext_changed(void);
int test_ind_cpa(void);
int test_invalid_ciphertext_enc(void);

int test_keys(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR keys\n");
    return 1;
  }

  return 0;
}

int test_invalid_sk_a(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Replace secret key with random values
  randombytes(sk, CRYPTO_SECRETKEYBYTES);

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid sk\n");
    return 1;
  }

  return 0;
}

int test_invalid_ciphertext(void)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];
  uint8_t b;
  size_t pos;

  do {
    randombytes(&b, sizeof(uint8_t));
  } while(!b);
  randombytes((uint8_t *)&pos, sizeof(size_t));

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Change some byte in the ciphertext (i.e., encapsulated key)
  ct[pos % CRYPTO_CIPHERTEXTBYTES] ^= b;

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid ciphertext\n");
    return 1;
  }

  return 0;
}




// int test_invalid_ciphertext_changed(void)
// {

//   // Key
//   uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {81,182,61,5,106,183,119,154,179,113,242,32,120,217,88,170,139,108,220,178,3,134,42,40,165,160,170,151,11,143,43,228,189,88,138,6,104,28,191,164,203,163,201,118,99,40,226,12,255,84,169,227,68,185,172,216,14,218,17,50,45,151,175,78,140,162,232,219,159,21,4,48,109,49,85,165,1,82,161,121,92,142,108,169,255,50,166,209,226,85,131,37,86,225,129,51,219,49,102,251,179,59,15,21,133,141,22,83,11,106,129,95,119,147,182,98,184,17,100,192,105,100,176,100,75,141,107,144,26,133,86,171,123,146,20,183,37,70,114,182,163,72,91,96,135,247,13,205,4,5,60,122,179,234,81,130,204,241,114,231,115,56,109,96,134,217,163,55,92,65,176,9,148,202,109,172,172,0,16,78,187,41,31,206,134,179,95,244,145,41,38,206,5,99,146,220,100,122,166,18,36,113,38,33,112,116,107,117,118,197,251,234,81,182,53,38,30,5,34,177,107,75,97,103,35,190,196,168,62,145,31,147,167,49,222,9,10,38,72,102,70,0,139,183,188,1,175,216,91,228,56,122,228,243,37,68,187,111,189,75,130,93,21,14,220,166,184,48,235,144,59,129,140,128,134,42,143,243,19,101,104,24,36,8,9,226,122,127,180,247,182,175,65,84,71,92,100,49,218,62,35,4,148,61,166,90,146,162,1,25,104,124,46,247,46,179,58,180,176,40,21,47,72,5,8,250,127,248,150,6,203,182,199,177,162,25,251,163,173,1,135,163,237,51,129,195,116,54,137,90,182,201,180,168,249,243,158,53,164,89,28,49,122,126,36,175,49,122,70,124,88,86,110,149,108,102,138,203,21,187,112,123,25,108,102,236,73,163,65,4,59,11,46,126,132,107,83,26,35,250,51,119,27,153,138,240,162,133,211,215,170,45,167,145,68,184,145,61,162,129,38,146,201,133,106,69,212,137,36,102,155,150,5,202,25,171,11,57,239,115,125,230,103,192,238,34,2,113,244,97,100,151,199,171,86,132,104,67,82,88,203,73,41,211,140,172,19,175,57,153,88,39,100,56,17,184,184,105,135,112,183,86,102,165,123,75,26,6,40,166,188,29,228,104,161,166,216,90,97,199,123,77,107,207,54,214,204,141,251,115,19,183,100,134,101,30,47,0,151,68,71,194,238,211,148,228,149,174,146,81,104,80,98,113,95,69,23,21,198,142,157,186,12,135,106,120,127,92,73,118,40,119,10,210,179,73,150,12,254,152,52,6,51,172,5,99,145,152,92,133,168,53,73,3,136,99,180,240,91,2,1,113,157,242,37,113,218,59,102,245,84,134,246,85,46,104,94,54,242,131,33,171,72,127,204,145,24,49,27,94,240,69,181,194,155,134,87,78,85,187,139,225,168,185,211,209,180,255,1,67,211,121,144,187,49,119,83,35,158,62,248,191,197,240,74,17,235,47,16,27,206,235,68,92,149,11,52,170,184,140,9,22,156,167,115,139,192,185,28,48,43,203,72,160,170,134,232,81,136,231,157,154,5,185,37,57,94,158,236,21,82,172,93,44,153,106,186,23,14,76,138,136,47,75,204,219,75,132,229,12,106,39,210,25,173,214,206,248,202,19,70,214,51,112,188,90,81,2,67,193,11,99,89,33,24,230,130,31,145,180,201,82,26,60,198,24,171,30,101,76,91,156,151,246,156,154,28,3,108,237,148,141,10,231,121,200,183,90,224,98,117,32,245,162,24,144,164,246,188,168,41,80,102,90,115,103,111,242,137,90,35,81,253,136,112,169,211,149,121,194,155,227,80,56,101,104,13,84,138,98,196,113,4,87,131,36,28,113,1,52,18,181,49,3,13,231,163,28,108,23,102,57,44,129,55,7,178,29,156,57,58,169,79,103,213,89,243,0,60,152,70,182,153,119,168,8,102,95,84,70,204,232,145,105,163,7,103,20,40,51,116,149,37,126,154,109,248,195,169,220,102,21,100,211,188,10,121,64,197,241,2,165,72,139,221,170,187,147,184,149,133,162,95,165,145,101,70,216,173,217,81,108,237,121,41,213,209,129,210,20,36,50,151,81,135,1,118,209,177,117,143,10,10,122,247,61,189,233,150,217,226,133,202,32,112,124,72,54,37,177,59,195,215,51,56,196,82,183,8,174,103,161,202,239,144,158,238,144,75,201,166,2,122,105,79,200,246,12,220,37,14,186,176,1,71,11,121,100,152,120,38,32,191,216,85,129,156,248,164,129,40,76,199,227,53,87,132,87,3,26,150,73,44,147,122,225,97,240,88,97,166,150,204,28,184,199,185,49,70,121,172,182,120,2,146,114,233,153,95,104,22,7,129,28,216,48,140,81,35,86,11,198,63,128,89,157,51,10,104,215,84,9,161,149,44,207,154,13,255,140,194,236,7,105,66,5,115,174,214,144,212,151,192,91,236,4,27,5,171,183,7,176,53,92,54,35,236,173,68,199,20,188,198,133,227,199,191,155,171,160,13,248,153,45,145,53,118,84,40,116,133,5,193,232,34,146,252,3,139,6,115,63,3,3,196,18,171,244,54,40,149,215,22,232,91,10,11,34,185,34,216,195,253,68,142,254,150,97,171,179,160,230,188,80,16,250,39,38,70,50,124,29,98,11,109,142,205,133,157,243,64,253,100,233};
//   uint8_t sk[CRYPTO_SECRETKEYBYTES] = {176,133,154,52,40,174,4,112,171,12,54,58,124,176,170,195,39,38,48,224,26,72,44,46,116,120,104,253,33,110,212,202,177,95,154,201,238,251,124,204,25,182,207,203,44,230,136,189,60,243,58,141,73,199,24,152,133,175,244,48,18,236,176,206,167,144,250,84,79,127,247,105,227,147,146,192,182,189,180,230,120,49,55,20,40,70,19,245,81,117,55,89,108,37,108,146,37,166,54,145,218,170,215,58,38,175,198,56,140,27,197,105,213,164,9,226,98,23,11,38,6,38,205,36,248,139,131,144,124,199,220,147,128,186,137,245,88,6,1,150,19,203,42,159,58,161,44,245,104,135,152,86,186,109,54,129,201,80,160,66,19,10,60,18,65,123,220,70,38,226,91,225,166,6,208,188,112,38,130,129,210,211,77,76,251,114,246,170,88,205,235,95,87,217,133,244,243,3,78,220,44,201,54,100,6,112,178,62,49,45,12,171,166,248,176,106,254,186,90,236,105,89,89,165,130,94,241,151,119,80,24,73,251,187,156,59,131,25,120,181,25,41,5,172,85,152,185,155,116,208,193,188,203,145,161,147,11,104,177,98,0,255,36,93,143,17,89,126,85,111,131,245,32,95,132,116,169,251,65,231,35,125,158,53,28,231,210,85,26,209,175,191,48,108,214,18,151,37,121,102,103,51,15,8,52,73,204,92,190,151,119,46,204,233,124,172,134,118,238,250,39,250,201,152,191,27,148,139,182,79,82,170,31,131,58,141,62,240,75,113,169,48,93,147,133,196,2,28,46,217,124,147,107,110,250,98,147,41,218,17,85,105,24,246,180,12,75,224,94,242,116,2,129,4,205,72,137,119,75,153,191,172,231,165,50,166,165,87,193,20,64,139,163,145,27,37,174,90,156,231,243,148,215,144,66,86,220,94,203,129,192,112,90,51,40,185,11,100,121,161,66,187,158,118,211,156,251,219,193,79,218,6,40,217,81,35,88,106,80,104,128,3,10,37,52,55,192,174,150,122,183,224,56,198,72,147,247,232,25,250,67,169,177,57,33,28,144,202,47,181,24,43,244,102,82,162,92,94,220,94,142,135,135,14,107,105,52,102,65,15,169,78,26,208,160,90,195,156,97,1,37,199,226,132,0,97,45,137,140,135,49,138,94,116,0,94,246,128,59,230,149,42,104,227,207,98,186,126,62,76,128,208,133,137,239,215,166,134,16,199,155,156,42,181,35,67,150,145,101,213,177,41,81,163,61,109,27,3,129,0,27,178,119,189,247,7,112,44,23,185,228,51,94,82,247,175,210,149,116,121,51,113,213,98,147,117,0,103,50,123,71,184,251,88,125,172,173,205,138,76,171,226,135,188,36,198,229,184,86,183,231,167,39,114,111,74,199,178,206,243,76,188,115,92,179,76,207,175,208,43,195,42,43,16,249,115,33,210,165,67,198,201,50,170,182,127,150,194,42,108,67,120,71,80,64,7,20,77,65,67,60,208,46,200,144,16,192,115,141,194,84,14,130,244,6,7,7,153,89,225,93,221,33,185,54,226,48,25,186,18,7,118,20,158,23,145,90,82,149,84,214,6,191,120,14,233,104,194,46,71,9,101,50,91,32,161,41,206,139,55,182,147,4,77,37,157,149,65,44,77,36,90,232,97,112,170,164,207,3,240,78,199,119,133,80,169,68,60,76,202,124,104,68,14,148,24,98,233,204,9,85,27,95,10,57,75,71,28,134,51,36,168,135,54,199,166,68,100,81,21,22,56,97,94,103,206,135,144,153,233,53,120,178,121,21,2,104,149,157,21,138,222,4,203,35,211,107,136,18,54,72,20,25,247,129,162,135,123,166,4,182,86,57,76,129,171,7,204,190,65,150,243,148,200,223,235,36,109,36,145,220,113,47,141,68,161,107,23,104,34,160,79,255,168,65,128,7,71,243,185,191,142,108,38,237,80,58,173,212,115,226,123,55,28,231,38,206,179,26,151,50,140,173,196,49,85,107,66,62,193,11,170,198,97,40,240,64,103,41,37,209,112,121,176,229,193,156,198,194,246,192,119,253,66,46,221,26,65,137,146,186,187,244,189,160,151,145,89,199,53,27,58,41,52,201,37,183,36,71,3,76,40,15,65,67,223,27,134,5,196,195,124,55,28,194,119,135,173,137,125,112,17,50,23,204,29,217,250,160,136,90,94,58,146,21,36,24,90,2,86,79,188,72,110,59,155,0,179,132,178,100,186,33,111,101,181,48,236,32,204,128,103,16,137,52,183,152,179,69,184,39,52,108,95,109,35,7,105,44,121,82,37,173,64,228,152,144,106,57,188,240,186,128,185,75,230,136,91,225,39,6,183,144,158,154,212,11,178,71,151,197,218,4,22,183,102,147,119,201,230,25,38,196,200,102,41,37,46,163,8,57,55,58,151,250,108,138,87,145,144,144,168,197,26,201,189,82,68,133,227,91,185,118,232,138,36,178,190,37,201,76,115,92,51,0,21,67,221,0,146,36,138,29,60,81,29,105,27,42,105,106,23,122,68,99,222,113,205,186,38,57,80,123,173,31,182,194,163,85,165,147,5,203,150,131,34,75,41,115,96,234,198};
//   memcpy(sk+KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
//   hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
//   /* Value z for pseudo-random output on reject */
//   uint8_t coins[KYBER_SYMBYTES];
//   randombytes(coins, KYBER_SYMBYTES);
//   memcpy(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, coins, KYBER_SYMBYTES);

//   uint8_t m[32] = {200,184,203,220,154,132,26,30,75,58,196,49,65,208,180,170,184,112,176,24,76,15,150,32,60,6,164,183,223,4,27,49};
//   uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
//   uint8_t key_a[CRYPTO_BYTES];
//   uint8_t key_b[CRYPTO_BYTES];

//   printf("orginal messsage\n");
//   for (int i = 0; i < 32; i++)
//     printf("%u,", m[i]);
//   printf("\n\n");
//   //uint8_t b;
//   //size_t pos;

//   // do {
//   //   randombytes(&b, sizeof(uint8_t));
//   // } while(!b);
//   // randombytes((uint8_t *)&pos, sizeof(size_t));

//   //Alice generates a public key
//   //crypto_kem_keypair(pk, sk);

//   //Bob derives a secret key and creates a response
//   crypto_kem_enc_mod_m(ct, key_b, pk, m);
//   printf("orginal cipher text:\n");
//   for (int i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++)
//     printf("%u", ct[i]);
//   printf("\n\n");
//   //Change some byte in the ciphertext (i.e., encapsulated key)
//   //ct[pos % CRYPTO_CIPHERTEXTBYTES] ^= b;
//   uint8_t ct_modif[CRYPTO_CIPHERTEXTBYTES] = {1,130,14,28,251,3,8,39,94,162,253,212,125,174,95,249,128,140,96,166,249,122,79,66,233,2,111,107,205,40,45,253,75,251,227,45,191,0,149,248,98,202,201,198,57,41,215,189,85,71,107,175,58,225,185,87,186,253,51,247,207,20,57,118,24,208,222,68,115,249,181,58,15,44,165,0,50,183,5,6,62,96,43,37,21,96,85,200,19,239,182,138,55,68,83,255,14,27,61,216,17,199,147,125,207,92,254,180,48,9,43,88,8,240,135,129,183,28,223,212,82,36,55,236,72,43,138,190,217,68,12,5,227,112,214,245,110,115,136,228,91,215,122,113,142,150,202,21,155,139,146,234,13,146,107,108,212,209,240,201,94,145,252,132,94,202,177,13,181,7,168,87,87,203,62,162,207,195,93,81,2,122,245,241,50,58,54,220,176,9,176,85,228,209,123,158,212,31,97,101,219,59,16,178,134,188,72,6,100,219,21,224,234,35,96,105,139,195,183,146,57,22,234,60,209,120,55,135,170,64,17,49,121,20,163,245,142,111,30,198,92,102,117,242,181,6,224,91,120,20,119,113,105,41,143,192,60,45,7,99,138,80,53,45,5,155,92,190,141,135,216,197,255,70,128,158,151,127,253,23,109,146,4,177,43,118,124,30,56,43,208,173,246,133,228,242,180,25,107,91,131,118,110,116,28,158,230,243,168,115,51,61,209,126,201,17,230,99,36,114,55,153,136,249,245,40,124,212,83,237,90,32,130,182,41,214,255,46,118,29,188,136,119,240,96,205,251,85,189,251,128,46,153,141,22,190,9,213,74,113,92,46,198,231,179,102,113,199,158,110,252,48,161,222,148,31,27,31,187,125,68,163,190,143,142,142,151,16,12,94,14,59,230,125,80,190,142,169,183,100,222,165,202,140,220,69,21,88,147,130,127,132,100,72,193,155,125,17,98,158,230,155,82,228,45,126,16,18,75,159,37,117,233,62,210,255,75,53,12,134,211,233,17,0,82,248,57,12,30,229,190,211,232,210,33,2,181,168,139,223,24,183,52,99,158,68,70,250,195,144,59,229,64,35,140,198,194,195,49,180,172,174,121,184,227,173,134,5,136,184,174,141,108,66,197,39,44,77,49,65,36,25,232,53,151,197,211,36,249,238,103,23,21,229,106,33,4,58,2,3,158,200,38,180,200,83,146,118,157,28,238,159,59,223,200,36,254,62,181,98,191,114,195,244,29,159,179,82,123,117,152,51,50,101,45,79,35,211,39,187,187,186,249,114,252,82,53,130,97,18,169,57,67,49,149,73,241,126,144,14,255,98,224,143,185,42,67,219,110,38,217,221,229,64,46,185,195,237,129,94,22,228,85,160,114,142,62,249,183,102,174,29,205,0,141,113,64,162,228,168,21,100,209,54,128,151,215,246,38,169,193,131,186,249,255,212,63,110,58,231,248,2,123,29,9,204,157,240,198,55,223,228,169,116,125,91,7,192,157,59,95,163,174,49,198,91,215,245,118,44,225,228,51,125,119,165,219,239,11,178,57,252,128,132,123,157,40,190,170,179,45,76,58,168,22,102,172,77,79,206,69,128,175,189,195,39,246,106,20,132,101,114,132,159,255,176,239,171,218,21,175,188,129,77,192,139,183,170,10,69,90,95,60,174,140,118,233,109,243,71,251,39,248,118,172,176,216,79,3,217,110,163,113,183,31,66,216,235,88,251,162,35,241,201,144,66,60,148,242,58,151,75,46,92,149,87,74,207,242,32,148,102,31,148,119,176,102,87,14,36,139,43,41,201,214,64,207,114,15,32,223,162,223,83,53,230,226,103,89,37,210,255,72,40,1,116,51,121,39,25,20,143,9,160,162,241,231,133,26,42,70,60,199,25,96,58,193,234,125,91,111,195,176,131,190,81,183,113,88,97,141,112,226,137,67,71,81,17,203,157,83,243,200,207,169,219,237,226,105,92,142,208,233,105,235,36,62,173,215,222,112,59,60,109,56,199,234,119,36,156,168,117,221,149,146,47,235,147,21,82,12,123,142,90,228,144,45,189,41,116,77,226,117,73,42,103,18,83,161,255,12,92,46,67,176,35,216,213,82,211,23,42,117,55,153,153,123,135,141,221,97,103,63,85,82,43,255,170,216,146,191,26,199,50,119,181,81,153,66,221,99,110,100,196,187,90,109,129,250,248,25,29,253,48,25,11,71,243,12,10,168,110,108,226,2,106,59,69,255,139,226,42,104,66,145,140,108,243,194,1,134,160,10,63,127,195,225,95,133,241,122,159,166,252,127,48,173,137,236,160,84,140,202,240,229,248,81,26,1,20,135,223,182,233,65,107,182,91,156,13,253,51,66,109,39,0,229,176,223,20,188,105,5,130,117,61,90,148,250,206,91,14,203,167,174,248,137,81,116,182,200,241,117,33,88,4,16,254,27,194,19,104,171,220,92,250,5,180};

//   printf("modified cipher text:\n");
//   for (int i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++)
//     printf("%u", ct_modif[i]);
//   printf("\n\n");

//   //Alice uses Bobs response to get her shared key
//   crypto_kem_dec(key_a, ct_modif, sk);

//   indcpa_dec(m, ct_modif, sk);

//     printf("decrypted messsage\n");
//     for (int i = 0; i < 32; i++)
//       printf("%u,", m[i]);
//     printf("\n\n");

//   if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
//     printf("ERROR invalid ciphertext\n");
//     return 1;
//   }

//   return 0;
// }

int test_ind_cpa(void)
{
   uint8_t m_test[KYBER_INDCPA_MSGBYTES] = {3, 195, 74, 31, 61, 83, 182, 38, 99, 32, 64, 131, 127, 99, 197, 22, 91, 62, 168, 209, 113, 159, 224, 185, 31, 201, 47, 27, 136, 27, 176, 98};


  // Key generation
  uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES] = {0};
  uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES] = {0};

  uint8_t coins[KYBER_SYMBYTES] = {0};
  randombytes(coins, KYBER_SYMBYTES);
  indcpa_keypair_derand(pk, sk, coins);

  // Encryption 1
  uint8_t ct_org[KYBER_INDCPA_BYTES] = {0};
  uint8_t buf[2*KYBER_SYMBYTES] = {0};
  uint8_t kr[2*KYBER_SYMBYTES] = {0};
  memcpy(buf, m_test, KYBER_SYMBYTES);
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);   //TODO: add cpucycles mesurement
  hash_g(kr, buf, 2*KYBER_SYMBYTES);
  indcpa_enc(ct_org, buf, pk, kr+KYBER_SYMBYTES);

  printf("orginal message:\n");
  for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++)
    printf("%u", m_test[i]);
  printf("\n\n");

  printf("orginal cipher text:\n");
  for (int i = 0; i < KYBER_INDCPA_BYTES; i++)
    printf("%u", ct_org[i]);
  printf("\n\n");

  //Re-encryption with same message and key
  uint8_t ct_org1[KYBER_INDCPA_BYTES] = {0};
  memset(buf, 0, sizeof(buf));
  //memset(kr, 0, sizeof(kr));
  memcpy(buf, m_test, KYBER_SYMBYTES);
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);   //TODO: add cpucycles mesurement
  //hash_g(kr, buf, 2*KYBER_SYMBYTES);
  indcpa_enc(ct_org1, buf, pk, kr+KYBER_SYMBYTES);

  printf("orginal message:\n");
  for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++)
    printf("%u", m_test[i]);
  printf("\n\n");

  printf("orginal cipher text:\n");
  for (int i = 0; i < KYBER_INDCPA_BYTES; i++)
    printf("%u", ct_org1[i]);
  printf("\n\n");

  if(memcmp(ct_org1, ct_org, KYBER_INDCPA_BYTES)) {
    printf("ct_org1 and c_org are different\n\n");
  }


  //Re-encryption with same message (but first byte changed) and key
  m_test[0] = 2;
  uint8_t ct_org2[KYBER_INDCPA_BYTES] = {0};
  memset(buf, 0, sizeof(buf));
  //memset(kr, 0, sizeof(kr));
  memcpy(buf, m_test, KYBER_SYMBYTES);
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);   //TODO: add cpucycles mesurement
  //hash_g(kr, buf, 2*KYBER_SYMBYTES);
  indcpa_enc(ct_org2, buf, pk, kr+KYBER_SYMBYTES);

  printf("orginal message:\n");
  for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++)
    printf("%u", m_test[i]);
  printf("\n\n");

  printf("orginal cipher text:\n");
  for (int i = 0; i < KYBER_INDCPA_BYTES; i++)
    printf("%u", ct_org2[i]);
  printf("\n\n");

  if(memcmp(ct_org2, ct_org, KYBER_INDCPA_BYTES)) {
    printf("ct_org2 and c_org are different\n\n");
  }

  if(memcmp(ct_org2, ct_org1, KYBER_INDCPA_BYTES)) {
    printf("ct_org2 and c_org1 are different\n\n");
  }

  return 0;

} 



int test_invalid_ciphertext_enc(void)
{
  // Key generation
  uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES] = {0};
  uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES] = {0};

  uint8_t coins[KYBER_SYMBYTES] = {0};
  randombytes(coins, KYBER_SYMBYTES);
  indcpa_keypair_derand(pk, sk, coins);


  printf("public key:\n");
  for (int i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++)
    printf("%u,", pk[i]);
  printf("\n\n");

  printf("secret key:\n");
  for (int i = 0; i < KYBER_INDCPA_SECRETKEYBYTES; i++)
    printf("%u,", sk[i]);
  printf("\n\n");

  // Encryption 1
  uint8_t m_org[KYBER_INDCPA_MSGBYTES] = {0};
  uint8_t ct_org[KYBER_INDCPA_BYTES] = {0};
  randombytes(m_org, KYBER_SYMBYTES);
  uint8_t buf[2*KYBER_SYMBYTES] = {0};
  uint8_t kr[2*KYBER_SYMBYTES] = {0};
  memcpy(buf, m_org, KYBER_SYMBYTES);
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);   //TODO: add cpucycles mesurement
  hash_g(kr, buf, 2*KYBER_SYMBYTES);
  indcpa_enc(ct_org, buf, pk, kr+KYBER_SYMBYTES);

  printf("orginal message:\n");
  for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++)
    printf("%u", m_org[i]);
  printf("\n\n");

  printf("orginal cipher text:\n");
  for (int i = 0; i < KYBER_INDCPA_BYTES; i++)
    printf("%u", ct_org[i]);
  printf("\n\n");

  
  // Decryption 1
  uint8_t dec_m_org[KYBER_INDCPA_MSGBYTES] = {0};
  indcpa_dec(dec_m_org, ct_org, sk);

  printf("decrypted orginal message:\n");
  for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++)
    printf("%u,", dec_m_org[i]);
  printf("\n\n");

  if(memcmp(m_org, dec_m_org, KYBER_INDCPA_MSGBYTES)) {
    printf("Decryption error!\n\n");
    return 1;
  }


  // Cipher text modify
  uint8_t ct_modified[KYBER_INDCPA_BYTES] = {0};
  uint8_t b;
  size_t pos;
  do {
    randombytes(&b, sizeof(uint8_t));
  } while(!b);
  randombytes((uint8_t *)&pos, sizeof(size_t));

  memcpy(ct_modified, ct_org, KYBER_INDCPA_BYTES);
  printf("before: %u\n", ct_modified[pos % KYBER_INDCPA_BYTES]);
  ct_modified[pos % KYBER_INDCPA_BYTES] ^= b;
  printf("after: %u\n\n\n", ct_modified[pos % KYBER_INDCPA_BYTES]);

  printf("modified cipher text:\n");
  for (int i = 0; i < KYBER_INDCPA_BYTES; i++)
    printf("%u,", ct_modified[i]);
  printf("\n\n");

  if(memcmp(ct_modified, ct_org, KYBER_INDCPA_BYTES)) {
    printf("c_modified and c_org are different\n\n");
  }



  // Decrypt modified ciphertext and compare the message 
  uint8_t m_modified[KYBER_INDCPA_MSGBYTES] = {0};
  indcpa_dec(m_modified, ct_modified, sk);

  printf("decrypted ct_modified (modified message):\n");
  for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++)
    printf("%u", m_modified[i]);
  printf("\n\n");

  if(memcmp(m_modified, m_org, KYBER_INDCPA_MSGBYTES)) {
    printf("m_modified and m_ord are different!\n\n");
    //return 0;
  }

  if(memcmp(m_modified, dec_m_org, KYBER_INDCPA_MSGBYTES)) {
    printf("m_modified and dec_m_org are different!\n\n");
    //return 0;
  }

  //Encrypt modified message and compare with modified ciphertext
  uint8_t ct_enc_modified_m[KYBER_INDCPA_BYTES] = {0};
  memset(buf, 0, sizeof(buf));
  memset(kr, 0, sizeof(kr));
  memcpy(buf, m_modified, KYBER_SYMBYTES);
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_INDCPA_PUBLICKEYBYTES);   //TODO: add cpucycles mesurement
  hash_g(kr, buf, 2*KYBER_SYMBYTES);
  indcpa_enc(ct_enc_modified_m, buf, pk, kr+KYBER_SYMBYTES);

  printf("modified message:\n");
  for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++)
    printf("%u", m_modified[i]);
  printf("\n\n");

  printf("ciphertext of modified message:\n");
  for (int i = 0; i < KYBER_INDCPA_BYTES; i++)
    printf("%u", ct_enc_modified_m[i]);
  printf("\n\n");

  if(memcmp(ct_enc_modified_m, ct_modified, KYBER_INDCPA_BYTES)) {
    printf("ct_enc_modified_m and ct_modified are different\n\n");
  }



  // Decryption of ct_enc_modified_m and comprare if matches with m_modified
  uint8_t dec_m_ct_enc_modified_m[KYBER_INDCPA_MSGBYTES] = {0};
  indcpa_dec(dec_m_ct_enc_modified_m, ct_enc_modified_m, sk);

  printf("Decryption of ct_enc_modified_m:\n");
  for (int i = 0; i < KYBER_INDCPA_MSGBYTES; i++)
    printf("%u", dec_m_ct_enc_modified_m[i]);
  printf("\n\n");

  if(memcmp(dec_m_ct_enc_modified_m, m_modified, KYBER_INDCPA_MSGBYTES)) {
    printf("dec_m_ct_enc_modified_m and m_modified are different\n\n");
    //return 1;
  }

  return 0;

  

}

int main(void)
{
  unsigned int i, ctr = 0;
  int r;

  for(i=0;i<NTESTS;i++) {
    r  = test_keys();
    r |= test_invalid_sk_a();
    r |= test_invalid_ciphertext();

    if (r)
      ctr++;
  }

  //test_invalid_ciphertext_changed();
  //test_invalid_ciphertext_enc();

  printf("%d times r was not 0\n", ctr);

  
  printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);

  getchar();
  return 0;
}

#else

#define NTESTS 1001

uint64_t t[NTESTS];
uint8_t seed[KYBER_SYMBYTES] = {0};

void measureHashes(void);

void measureHashes(void)
{
  // hash pk measure
  uint64_t t_in[NTESTS*2];
  uint64_t t_out[NTESTS];
  unsigned int i;

  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key[CRYPTO_BYTES];

  for (i=0; i<NTESTS*2; i+=2)
  {
    crypto_kem_keypair_mod(pk, sk, &t_in[i], &t_in[i+1]);
  }
  print_results_hash("Hash pk in KeyGen: ", t_out, t_in, NTESTS*2);



  for (i=0; i<NTESTS*2; i+=2)
  {
    crypto_kem_enc_mod(ct, key, pk, &t_in[i], &t_in[i+1]);
  }
  print_results_hash("Hash pk in Encaps: ", t_out, t_in, NTESTS*2);


  for (i=0; i<NTESTS*2; i+=2)
  {
    crypto_kem_dec_mod(key, ct, sk, &t_in[i], &t_in[i+1]);
  }
  print_results_hash("Hash in Decaps: ", t_out, t_in, NTESTS*2);
}


int main(void)
{


  printf("----------------------------------------------------");
  printf("Tests: %d\n", NTESTS);

  unsigned int i;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key[CRYPTO_BYTES];
  uint8_t coins32[KYBER_SYMBYTES];
  uint8_t coins64[2*KYBER_SYMBYTES];
  polyvec matrix[KYBER_K];
  poly ap;
  polyvec ap_vec;

  randombytes(coins32, KYBER_SYMBYTES);
  randombytes(coins64, 2*KYBER_SYMBYTES);


  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    randombytes(coins32, KYBER_SYMBYTES);
  }
  print_results("randombytes(coins32, KYBER_SYMBYTES) ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    randombytes(coins64, KYBER_SYMBYTES);
  }
  print_results("randombytes(coins64, KYBER_SYMBYTES) ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    gen_matrix(matrix, seed, 0);
  }
  print_results("gen_a: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_getnoise_eta1(&ap, seed, 0);
  }
  print_results("poly_getnoise_eta1: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_getnoise_eta2(&ap, seed, 0);
  }
  print_results("poly_getnoise_eta2: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_ntt(&ap);
  }
  print_results("NTT: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_invntt_tomont(&ap);
  }
  print_results("INVNTT: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    polyvec_basemul_acc_montgomery(&ap, &matrix[0], &matrix[1]);
  }
  print_results("polyvec_basemul_acc_montgomery: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_tomsg(ct,&ap);
  }
  print_results("poly_tomsg: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_frommsg(&ap,ct);
  }
  print_results("poly_frommsg: ", t, NTESTS);

    for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_frombytes(&ap,pk);
  }
  print_results("poly_frombytes: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_tobytes(pk,&ap);
  }
  print_results("poly_tobytes: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    polyvec_frombytes(&ap_vec,pk);
  }
  print_results("polyvec_frombytes: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    polyvec_tobytes(pk,&ap_vec);
  }
  print_results("polyvec_tobytes: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_compress(ct,&ap);
  }
  print_results("poly_compress: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    poly_decompress(&ap,ct);
  }
  print_results("poly_decompress: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    polyvec_compress(ct,&matrix[0]);
  }
  print_results("polyvec_compress: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    polyvec_decompress(&matrix[0],ct);
  }
  print_results("polyvec_decompress: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    indcpa_keypair_derand(pk, sk, coins32);
  }
  print_results("indcpa_keypair: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    indcpa_enc(ct, key, pk, seed);
  }
  print_results("indcpa_enc: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    indcpa_dec(key, ct, sk);
  }
  print_results("indcpa_dec: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_keypair_derand(pk, sk, coins64);
  }
  print_results("kyber_keypair_derand: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_keypair(pk, sk);
  }
  print_results("kyber_keypair: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_enc_derand(ct, key, pk, coins32);
  }
  print_results("kyber_encaps_derand: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_enc(ct, key, pk);
  }
  print_results("kyber_encaps: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    crypto_kem_dec(key, ct, sk);
  }
  print_results("kyber_decaps: ", t, NTESTS);

  //measureHashes();

  getchar();
  return 0;
}
#endif
