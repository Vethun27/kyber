// #include <stddef.h>
// #include <stdio.h>
// #include <string.h>
// #include "kem.h"
// #include "randombytes.h"
// #include <unistd.h>
// #include <stdint.h>
// #include <stdlib.h>
// #include "params.h"
// #include "indcpa.h"
// #include "polyvec.h"
// #include "poly.h"
// #include "cpucycles.h"
// #include "speed_print.h"


// #define NTESTS 1000

// static int test_keys(void)
// {
//   uint8_t pk[CRYPTO_PUBLICKEYBYTES];
//   uint8_t sk[CRYPTO_SECRETKEYBYTES];
//   uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
//   uint8_t key_a[CRYPTO_BYTES];
//   uint8_t key_b[CRYPTO_BYTES];

//   //Alice generates a public key
//   crypto_kem_keypair(pk, sk);

//   //Bob derives a secret key and creates a response
//   crypto_kem_enc(ct, key_b, pk);

//   //Alice uses Bobs response to get her shared key
//   crypto_kem_dec(key_a, ct, sk);

//   if(memcmp(key_a, key_b, CRYPTO_BYTES)) {
//     printf("ERROR keys\n");
//     return 1;
//   }

//   return 0;
// }

// static int test_invalid_sk_a(void)
// {
//   uint8_t pk[CRYPTO_PUBLICKEYBYTES];
//   uint8_t sk[CRYPTO_SECRETKEYBYTES];
//   uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
//   uint8_t key_a[CRYPTO_BYTES];
//   uint8_t key_b[CRYPTO_BYTES];

//   //Alice generates a public key
//   crypto_kem_keypair(pk, sk);

//   //Bob derives a secret key and creates a response
//   crypto_kem_enc(ct, key_b, pk);

//   //Replace secret key with random values
//   randombytes(sk, CRYPTO_SECRETKEYBYTES);

//   //Alice uses Bobs response to get her shared key
//   crypto_kem_dec(key_a, ct, sk);

//   if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
//     printf("ERROR invalid sk\n");
//     return 1;
//   }

//   return 0;
// }

// static int test_invalid_ciphertext(void)
// {
//   uint8_t pk[CRYPTO_PUBLICKEYBYTES];
//   uint8_t sk[CRYPTO_SECRETKEYBYTES];
//   uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
//   uint8_t key_a[CRYPTO_BYTES];
//   uint8_t key_b[CRYPTO_BYTES];
//   uint8_t b;
//   size_t pos;

//   do {
//     randombytes(&b, sizeof(uint8_t));
//   } while(!b);
//   randombytes((uint8_t *)&pos, sizeof(size_t));

//   //Alice generates a public key
//   crypto_kem_keypair(pk, sk);

//   //Bob derives a secret key and creates a response
//   crypto_kem_enc(ct, key_b, pk);

//   //Change some byte in the ciphertext (i.e., encapsulated key)
//   ct[pos % CRYPTO_CIPHERTEXTBYTES] ^= b;

//   //Alice uses Bobs response to get her shared key
//   crypto_kem_dec(key_a, ct, sk);

//   if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
//     printf("ERROR invalid ciphertext\n");
//     return 1;
//   }

//   return 0;
// }

// int main(void)
// {
//   unsigned int i;
//   int r;

//   for(i=0;i<NTESTS;i++) {
//     r  = test_keys();
//     r |= test_invalid_sk_a();
//     r |= test_invalid_ciphertext();
//     if(r)
//       return 1;
//   }

//   printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
//   printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
//   printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);

//   getchar();
//   return 0;
// }



// #define NTESTS 1000

// uint64_t t[NTESTS];
// uint8_t seed[KYBER_SYMBYTES] = {0};

// int main(void)
// {
//   unsigned int i;
//   uint8_t pk[CRYPTO_PUBLICKEYBYTES];
//   uint8_t sk[CRYPTO_SECRETKEYBYTES];
//   uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
//   uint8_t key[CRYPTO_BYTES];
//   uint8_t coins32[KYBER_SYMBYTES];
//   uint8_t coins64[2*KYBER_SYMBYTES];
//   polyvec matrix[KYBER_K];
//   poly ap;

//   randombytes(coins32, KYBER_SYMBYTES);
//   randombytes(coins64, 2*KYBER_SYMBYTES);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     gen_matrix(matrix, seed, 0);
//   }
//   print_results("gen_a: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     poly_getnoise_eta1(&ap, seed, 0);
//   }
//   print_results("poly_getnoise_eta1: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     poly_getnoise_eta2(&ap, seed, 0);
//   }
//   print_results("poly_getnoise_eta2: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     poly_ntt(&ap);
//   }
//   print_results("NTT: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     poly_invntt_tomont(&ap);
//   }
//   print_results("INVNTT: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     polyvec_basemul_acc_montgomery(&ap, &matrix[0], &matrix[1]);
//   }
//   print_results("polyvec_basemul_acc_montgomery: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     poly_tomsg(ct,&ap);
//   }
//   print_results("poly_tomsg: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     poly_frommsg(&ap,ct);
//   }
//   print_results("poly_frommsg: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     poly_compress(ct,&ap);
//   }
//   print_results("poly_compress: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     poly_decompress(&ap,ct);
//   }
//   print_results("poly_decompress: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     polyvec_compress(ct,&matrix[0]);
//   }
//   print_results("polyvec_compress: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     polyvec_decompress(&matrix[0],ct);
//   }
//   print_results("polyvec_decompress: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     indcpa_keypair_derand(pk, sk, coins32);
//   }
//   print_results("indcpa_keypair: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     indcpa_enc(ct, key, pk, seed);
//   }
//   print_results("indcpa_enc: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     indcpa_dec(key, ct, sk);
//   }
//   print_results("indcpa_dec: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     crypto_kem_keypair_derand(pk, sk, coins64);
//   }
//   print_results("kyber_keypair_derand: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     crypto_kem_keypair(pk, sk);
//   }
//   print_results("kyber_keypair: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     crypto_kem_enc_derand(ct, key, pk, coins32);
//   }
//   print_results("kyber_encaps_derand: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     crypto_kem_enc(ct, key, pk);
//   }
//   print_results("kyber_encaps: ", t, NTESTS);

//   for(i=0;i<NTESTS;i++) {
//     t[i] = cpucycles();
//     crypto_kem_dec(key, ct, sk);
//   }
//   print_results("kyber_decaps: ", t, NTESTS);

//   getchar();
//   return 0;
// }
