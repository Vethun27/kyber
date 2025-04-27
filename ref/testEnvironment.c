// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <openssl/rsa.h>
// #include <openssl/pem.h>
// #include <openssl/rand.h>
// #include <openssl/err.h>

// #define RSA_KEY_SIZE 2048
// #define SYMMETRIC_KEY_SIZE 32

// void handle_errors() {
//     ERR_print_errors_fp(stderr);
//     exit(EXIT_FAILURE);
// }

// RSA* generate_rsa_keypair() {
//     RSA* rsa = RSA_new();
//     BIGNUM* e = BN_new();
//     if (!rsa || !e) handle_errors();
    
//     if (!BN_set_word(e, RSA_F4)) handle_errors();
//     if (!RSA_generate_key_ex(rsa, RSA_KEY_SIZE, e, NULL)) handle_errors();
    
//     BN_free(e);
//     return rsa;
// }

// void encapsulate(RSA* rsa, unsigned char* sym_key, unsigned char* enc_key, int* enc_key_len) {
//     if (!RAND_bytes(sym_key, SYMMETRIC_KEY_SIZE)) handle_errors();
    
//     *enc_key_len = RSA_public_encrypt(SYMMETRIC_KEY_SIZE, sym_key, enc_key, rsa, RSA_PKCS1_OAEP_PADDING);
//     if (*enc_key_len == -1) handle_errors();
// }

// void decapsulate(RSA* rsa, unsigned char* enc_key, int enc_key_len, unsigned char* dec_key) {
//     int dec_len = RSA_private_decrypt(enc_key_len, enc_key, dec_key, rsa, RSA_PKCS1_OAEP_PADDING);
//     if (dec_len == -1) handle_errors();
// }

// int main() {
//     RSA* rsa = generate_rsa_keypair();
//     unsigned char sym_key[SYMMETRIC_KEY_SIZE];
//     unsigned char enc_key[RSA_KEY_SIZE / 8];
//     unsigned char dec_key[SYMMETRIC_KEY_SIZE];
//     int enc_key_len;

//     encapsulate(rsa, sym_key, enc_key, &enc_key_len);
//     decapsulate(rsa, enc_key, enc_key_len, dec_key);

//     if (memcmp(sym_key, dec_key, SYMMETRIC_KEY_SIZE) == 0) {
//         printf("Key encapsulation and decapsulation successful!\n");
//     } else {
//         printf("Key mismatch!\n");
//     }

//     RSA_free(rsa);

//     getchar();
//     return 0;
// }
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// #include <stdio.h>
// #include <openssl/rsa.h>
// #include <openssl/pem.h>
// #include <openssl/err.h>
// #include <openssl/sha.h>
// #include <string.h>

// size_t k = 1024;

// // Function to handle errors
// void handle_errors() {
//     ERR_print_errors_fp(stderr);
//     abort();
// }

// // Generate RSA key pair (private and public) with a 2048-bit key size
// RSA *generate_RSA_key_pair() {
//     RSA *rsa = RSA_new();
//     BIGNUM *bn = BN_new();

//     if (!BN_set_word(bn, RSA_F4)) {
//         handle_errors();
//     }

//     // Generating RSA key with k-bit key size
//     if (RSA_generate_key_ex(rsa, k, bn, NULL) != 1) {
//         handle_errors();
//     }

//     BN_free(bn);
//     return rsa;
// }

// // Encrypt a message using RSA public key (KEM)
// int encrypt_RSA(RSA *public_key, unsigned char *data, size_t data_len, unsigned char *encrypted) {
//     int result = RSA_public_encrypt(data_len, data, encrypted, public_key, RSA_PKCS1_OAEP_PADDING);
//     if (result == -1) {
//         handle_errors();
//     }
//     return result;
// }

// // Decrypt a message using RSA private key
// int decrypt_RSA(RSA *private_key, unsigned char *encrypted, size_t encrypted_len, unsigned char *decrypted) {
//     int result = RSA_private_decrypt(encrypted_len, encrypted, decrypted, private_key, RSA_PKCS1_OAEP_PADDING);
//     if (result == -1) {
//         handle_errors();
//     }
//     return result;
// }

// // Hash the shared secret using SHA-256 to get a symmetric key
// void hash_shared_secret(unsigned char *shared_secret, size_t secret_len, unsigned char *symmetric_key) {
//     SHA256_CTX sha256_ctx;
//     if (SHA256_Init(&sha256_ctx) != 1) {
//         handle_errors();
//     }

//     if (SHA256_Update(&sha256_ctx, shared_secret, secret_len) != 1) {
//         handle_errors();
//     }

//     if (SHA256_Final(symmetric_key, &sha256_ctx) != 1) {
//         handle_errors();
//     }
// }

// // Hash the shared secret using SHA-1 to get a symmetric key
// void hash_shared_secret_sha1(unsigned char *shared_secret, size_t secret_len, unsigned char *symmetric_key) {
//   SHA_CTX sha1_ctx;
//   if (SHA1_Init(&sha1_ctx) != 1) {
//       handle_errors();
//   }

//   if (SHA1_Update(&sha1_ctx, shared_secret, secret_len) != 1) {
//       handle_errors();
//   }

//   if (SHA1_Final(symmetric_key, &sha1_ctx) != 1) {
//       handle_errors();
//   }
// }

// int main() {
//     // Step 1: Generate RSA key pair (k-bit key size)
//     RSA *private_key = generate_RSA_key_pair();
//     RSA *public_key = RSAPublicKey_dup(private_key); // Public key from private key

//     DH_get_1024_160

//     // Step 2: Generate a shared secret (random symmetric key)
//     unsigned char shared_secret[38]; // Example k/8-byte shared secret
//     if (!RAND_bytes(shared_secret, sizeof(shared_secret))) {
//         handle_errors();
//     }

//     printf("Generated shared secret:\n");
//     printf("shared secret length: %ld\n", sizeof(shared_secret));
//     for (int i = 0; i < sizeof(shared_secret); i++) {
//         printf("%02x", shared_secret[i]);
//     }
//     printf("\n");

//     // Step 3: Encrypt the shared secret using RSA public key (KEM)
//     unsigned char encrypted_shared_secret[RSA_size(public_key)];
//     int encrypted_len = encrypt_RSA(public_key, shared_secret, sizeof(shared_secret), encrypted_shared_secret);

//     printf("Encrypted shared secret (RSA ciphertext):\n");
//     printf("Encrypted shared secret length: %ld\n", encrypted_len);
//     for (int i = 0; i < encrypted_len; i++) {
//         printf("%02x", encrypted_shared_secret[i]);
//     }
//     printf("\n");

//     // Step 4: Decrypt the shared secret using RSA private key
//     unsigned char decrypted_shared_secret[sizeof(shared_secret)];
//     int decrypted_len = decrypt_RSA(private_key, encrypted_shared_secret, encrypted_len, decrypted_shared_secret);

//     printf("Decrypted shared secret:\n");
//     printf("Decrypted shared secret length: %ld\n", decrypted_len);
//     for (int i = 0; i < decrypted_len; i++) {
//         printf("%02x", decrypted_shared_secret[i]);
//     }
//     printf("\n");

//     // Step 5: Hash the shared secret (now decrypted) to create the symmetric key
//     unsigned char symmetric_key[SHA_DIGEST_LENGTH];
//     hash_shared_secret_sha1(decrypted_shared_secret, decrypted_len, symmetric_key);

//     printf("Symmetric key (hashed shared secret):\n");
//     printf("hashed shared secret length: %d\n", sizeof(symmetric_key));
//     for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
//         printf("%02x", symmetric_key[i]);
//     }
//     printf("\n");

//     // Clean up
//     RSA_free(private_key);
//     RSA_free(public_key);

//     return 0;
// }

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// #include <stdio.h>
// #include <openssl/evp.h>
// #include <openssl/dh.h>
// #include <openssl/rand.h>
// #include <openssl/err.h>
// #include <string.h>

// #define DH_KEY_SIZE 2048
// #define DH_N_SIZE 160
// #define DH_GENERATOR 2

// void handle_errors() {
//     ERR_print_errors_fp(stderr);
//     exit(EXIT_FAILURE);
// }

// EVP_PKEY *generate_dh_params() {
//     EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
//     if (!pctx) handle_errors();
    
//     if (EVP_PKEY_paramgen_init(pctx) <= 0) handle_errors();
//     if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, DH_KEY_SIZE) <= 0) handle_errors();
//     //if (EVP_PKEY_CTX_set_dh_paramgen_subprime_len(pctx, DH_KEY_SIZE) <= 0) handle_errors();
//     if (EVP_PKEY_CTX_set_dh_paramgen_generator(pctx, DH_GENERATOR) <= 0) handle_errors();
//     //if (EVP_PKEY_CTX_set_dh_nid(pctx, NID_ffdhe3072) <= 0) handle_errors();
//     EVP_PKEY *params = NULL;
//     if (EVP_PKEY_paramgen(pctx, &params) <= 0) handle_errors();
    
//     EVP_PKEY_CTX_free(pctx);
//     return params;
// }

// EVP_PKEY *generate_dh_keypair(EVP_PKEY *params) {
//     EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
//     if (!kctx) handle_errors();
    
//     if (EVP_PKEY_keygen_init(kctx) <= 0) handle_errors();
    
//     EVP_PKEY *keypair = NULL;
//     if (EVP_PKEY_keygen(kctx, &keypair) <= 0) handle_errors();

//     DH* dh = NULL;
//     const BIGNUM *p, *q, *g;
//     int p_len, q_len, g_len;
//     // Extract the DH object from the EVP_PKEY
//     dh = EVP_PKEY_get0_DH(keypair);
//     if (!dh) {
//         handle_errors();
//     }

//     // Get the values of p, q, and g from the DH structure
//     DH_get0_pqg(dh, &p, &q, &g);

//     // Retrieve the lengths (sizes) of p, q, and g
//     p_len = BN_num_bytes(p);  // Size of p in bytes
//     //q_len = BN_num_bytes(q);  // Size of q in bytes
//     g_len = BN_num_bytes(g);  // Size of g in bytes

//     // Print the sizes
//     printf("Size of p: %d bytes\n", p_len);
//     //printf("Size of q: %d bytes\n", q_len);
//     printf("Size of g: %d bytes\n", g_len);
    
    
//     EVP_PKEY_CTX_free(kctx);

//     return keypair;
// }

// unsigned char *derive_shared_secret(EVP_PKEY *privkey, EVP_PKEY *peerkey, size_t *secret_len) {
//     EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
//     if (!ctx) handle_errors();
    
//     if (EVP_PKEY_derive_init(ctx) <= 0) handle_errors();
//     if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) handle_errors();
    
//     if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) handle_errors();
    
//     unsigned char *secret = OPENSSL_malloc(*secret_len);
//     if (!secret) handle_errors();
    
//     if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0) handle_errors();
    
//     EVP_PKEY_CTX_free(ctx);
//     return secret;
// }

// int main() {


//     OpenSSL_add_all_algorithms();

//     EVP_PKEY *params = generate_dh_params();
//     EVP_PKEY *keypair_A = generate_dh_keypair(params);
//     EVP_PKEY *keypair_B = generate_dh_keypair(params);
    
//     size_t secret_len_A, secret_len_B;
//     unsigned char *secret_A = derive_shared_secret(keypair_A, keypair_B, &secret_len_A);
//     unsigned char *secret_B = derive_shared_secret(keypair_B, keypair_A, &secret_len_B);
    
//     if (secret_len_A == secret_len_B && memcmp(secret_A, secret_B, secret_len_A) == 0) {
//         printf("Shared secrets match!\n");
//     } else {
//         printf("Shared secrets do NOT match!\n");
//     }
    
//     EVP_PKEY_free(params);
//     EVP_PKEY_free(keypair_A);
//     EVP_PKEY_free(keypair_B);
//     OPENSSL_free(secret_A);
//     OPENSSL_free(secret_B);
    
//     EVP_cleanup();
//     return 0;
// }