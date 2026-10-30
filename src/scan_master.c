#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <CommonCrypto/CommonCryptor.h>
#include <dispatch/dispatch.h>
#elif defined(__linux__)
#include <openssl/evp.h>
#include <pthread.h>
#endif

static unsigned char target_ct[48];

static int hex2bin(const char *hex, unsigned char *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &out[i]) != 1) return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("C3RB3R Master Key Memory Hunter (C/Hardware-Accelerated)\n");
        printf("Usage: %s <mem_dump.bin> <footer_last_48_bytes_hex>\n", argv[0]);
        return 1;
    }

    if (hex2bin(argv[2], target_ct, 48) != 0) {
        fprintf(stderr, "Error: Invalid target hex (must be 48 bytes / 96 hex characters)\n");
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *mem = (unsigned char *)malloc(sz);
    if (!mem || fread(mem, 1, sz, f) != sz) { 
        perror("fread/malloc"); 
        fclose(f);
        return 1; 
    }
    fclose(f);

    printf("[*] Loaded %ld bytes (%.2f MB) from %s\n", sz, (double)sz / (1024 * 1024), argv[1]);
    printf("[*] Scanning candidates with 1-byte sliding window...\n");

    long max_offset = sz - 48;
    int found_count = 0;

#if defined(__APPLE__)
    long block_size = 65536;
    long num_blocks = (max_offset + block_size - 1) / block_size;
    __block int b_found = 0;

    dispatch_apply(num_blocks, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^(size_t b) {
        long start = b * block_size;
        long end = start + block_size;
        if (end > max_offset) end = max_offset;

        unsigned char pt[48];
        size_t moved = 0;

        for (long i = start; i < end; i++) {
            const unsigned char *cand = mem + i;
            if (cand[0] == 0 && cand[1] == 0 && cand[2] == 0 && cand[3] == 0) continue;
            if (cand[16] == 0 && cand[17] == 0 && cand[18] == 0 && cand[19] == 0) continue;

            const unsigned char *iv = cand;
            const unsigned char *key = cand + 16;

            CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0,
                                             key, 32,
                                             iv,
                                             target_ct, 48,
                                             pt, 48,
                                             &moved);
            if (status == kCCSuccess && memcmp(pt + 32, pt + 40, 8) == 0) {
                printf("\n[SUCCESS] Master Key Found at offset 0x%lx (%ld)!\n", i, i);
                printf("  Master IV:  ");
                for (int k = 0; k < 16; k++) printf("%02x", iv[k]);
                printf("\n  Master KEY: ");
                for (int k = 0; k < 32; k++) printf("%02x", key[k]);
                printf("\n  Full 48B:   ");
                for (int k = 0; k < 48; k++) printf("%02x", cand[k]);
                printf("\n  Nonce:      ");
                for (int k = 0; k < 8; k++) printf("%02x", pt[32+k]);
                printf("\n\n");
                b_found++;
            }
        }
    });
    found_count = b_found;
#else
    unsigned char pt[48];
    for (long i = 0; i < max_offset; i++) {
        const unsigned char *cand = mem + i;
        if (cand[0] == 0 && cand[1] == 0 && cand[2] == 0 && cand[3] == 0) continue;
        if (cand[16] == 0 && cand[17] == 0 && cand[18] == 0 && cand[19] == 0) continue;

        const unsigned char *iv = cand;
        const unsigned char *key = cand + 16;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        int outlen1 = 0, outlen2 = 0;
        EVP_DecryptUpdate(ctx, pt, &outlen1, target_ct, 48);
        EVP_DecryptFinal_ex(ctx, pt + outlen1, &outlen2);
        EVP_CIPHER_CTX_free(ctx);

        if (memcmp(pt + 32, pt + 40, 8) == 0) {
            printf("\n[SUCCESS] Master Key Found at offset 0x%lx (%ld)!\n", i, i);
            printf("  Master IV:  ");
            for (int k = 0; k < 16; k++) printf("%02x", iv[k]);
            printf("\n  Master KEY: ");
            for (int k = 0; k < 32; k++) printf("%02x", key[k]);
            printf("\n  Full 48B:   ");
            for (int k = 0; k < 48; k++) printf("%02x", cand[k]);
            printf("\n  Nonce:      ");
            for (int k = 0; k < 8; k++) printf("%02x", pt[32+k]);
            printf("\n\n");
            found_count++;
        }
    }
#endif

    printf("[*] Scan complete. Matches: %d\n", found_count);
    free(mem);
    return 0;
}
