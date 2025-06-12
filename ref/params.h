/*
 * Info:
 * For running the standardized parameter sets, set the following Compilerflags:
 * -DKYBER_K = k element {2,3,4}
 * -DSPEED = x element {0,1} (0 to run the test_kyber and 1 to run test_speed)
 * -DTEST = 0
 * 
 * For running a parameter set, which is not standardized (for test purpose), set the following Compilerflags:
 * -DKYBER_K = your chosen k
 * -DSPEED = x element {0,1} (0 to run the test_kyber and 1 to run test_speed)
 * -DTEST = 1
 * In the lines 51-55 the allowed values for the parameters can be set
 */

#ifndef PARAMS_H
#define PARAMS_H

#ifndef KYBER_K
#define KYBER_K 3	/* Change this for different security strengths */
#endif

#ifndef TEST
#define TEST 1
#endif

/* Don't change parameters below this line */
#if TEST == 0
#if   (KYBER_K == 2)
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_ref_##s
#elif (KYBER_K == 3)
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_ref_##s
#elif (KYBER_K == 4)
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_ref_##s
#else
#error "KYBER_K must be in {2,3,4}"
#endif
#else
#define KYBER_NAMESPACE(s) pqcrystals_kyberX_ref_##s
#endif


#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

#if TEST == 1
// use this for other variable parameters

#if KYBER_K == 3                                                //Values that can be set: any; Should match the value set for the compilerflag -DKYBER_K

#define KYBER_ETA1 2                                            //Values that can be set: 1, 2, 3, 4, 5, 6, 7
#define KYBER_ETA2 2                                            //Values that can be set: 1, 2, 3, 4, 5, 6, 7
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 192)            //Values that can be set: k*352, k*320, k*288, k*256, k*224, k*192, k*160 
#define KYBER_POLYCOMPRESSEDBYTES    128                        //Values that can be set: 224, 192, 160, 128, 96, 64, 32 
/*
 * KYBER_POLYVECCOMPRESSEDBYTES sets d_u and is represented with k * x, where x = d_u * (n/8), where n = 256:
 * d_u = 11 corresponds to x = 352
 * d_u = 10 corresponds to x = 320
 * d_u =  9 corresponds to x = 288
 * d_u =  8 corresponds to x = 256
 * d_u =  7 corresponds to x = 224
 * d_u =  6 corresponds to x = 192
 * d_u =  5 corresponds to x = 160
 * 
 * KYBER_POLYCOMPRESSEDBYTES sets d_v and is represented with x, where x = d_v * (n/8), where n = 256
 * d_v = 7 corresponds to x = 224
 * d_v = 6 corresponds to x = 192
 * d_v = 5 corresponds to x = 160
 * d_v = 4 corresponds to x = 128
 * d_v = 3 corresponds to x =  96
 * d_v = 2 corresponds to x =  64
 * d_v = 1 corresponds to x =  32
 * 
 */
#endif

#else

#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_ETA2 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_ETA2 2
#define KYBER_POLYCOMPRESSEDBYTES    128 
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_ETA2 2
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

#endif

#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)

#endif
