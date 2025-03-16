/* decryption.c
 *
 * Implements decryption for the three encryption methods:
 * 1. Linux command pipeline reversal – uses tail and sed.
 * 2. AES decryption using OpenSSL.
 * 3. SHA-based decryption by XOR-ing with the SHA256 digest.
 *
 * Compile with: gcc decryption.c -o decrypt -lcrypto
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#define HEADER_SIZE 4
#define IV_SIZE 16

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/* Method 1: Reverse Linux command encryption.
 * Uses tail to skip the 4-byte header ("GSA:") and sed to reverse the transliteration.
 */
void decrypt_gsa(const char *inputFile, const char *outputFile) {
    char command[1024];
    snprintf(command, sizeof(command),
        "tail -c +5 %s | sed 'y/BCDEFGHIJKLMNOPQRSTUVWXYZAbcdefghijklmnopqrstuvwxyza/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz/' > %s",
        inputFile, outputFile);
    if (system(command) == -1) {
        perror("Error executing system command");
        exit(EXIT_FAILURE);
    }
}

/* Method 2: AES decryption using OpenSSL.
 * Reads the file, verifies the header ("AES:"), then reads the next 16 bytes as the IV,
 * and the remainder is the ciphertext. A password is requested, and its SHA256 digest is used as the key.
 */
void decrypt_aes(const char *inputFile, const char *outputFile) {
    FILE *in = fopen(inputFile, "rb");
    if (!in) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }
    char header[HEADER_SIZE + 1] = {0};
    if (fread(header, 1, HEADER_SIZE, in) != HEADER_SIZE) {
        fprintf(stderr, "Error reading header\n");
        exit(EXIT_FAILURE);
    }
    if (strncmp(header, "AES:", HEADER_SIZE) != 0) {
        fprintf(stderr, "File does not appear to be AES encrypted\n");
        exit(EXIT_FAILURE);
    }

    unsigned char iv[IV_SIZE];
    if (fread(iv, 1, IV_SIZE, in) != IV_SIZE) {
        fprintf(stderr, "Error reading IV\n");
        exit(EXIT_FAILURE);
    }

    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    long ciphertext_len = file_size - HEADER_SIZE - IV_SIZE;
    rewind(in);
    fseek(in, HEADER_SIZE + IV_SIZE, SEEK_SET);
    unsigned char *ciphertext = malloc(ciphertext_len);
    if (fread(ciphertext, 1, ciphertext_len, in) != (size_t)ciphertext_len) {
        fprintf(stderr, "Error reading ciphertext\n");
        exit(EXIT_FAILURE);
    }
    fclose(in);

    char password[128];
    printf("Enter password for AES decryption: ");
    scanf("%127s", password);

    unsigned char key[32];
    SHA256((unsigned char*)password, strlen(password), key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    int plaintext_len = ciphertext_len;
    unsigned char *plaintext = malloc(plaintext_len);
    int len, total_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    total_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    total_len += len;

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    FILE *out = fopen(outputFile, "wb");
    if (!out) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }
    fwrite(plaintext, 1, total_len, out);
    fclose(out);
    free(plaintext);

    printf("AES decryption completed. Output saved to %s\n", outputFile);
}

/* Method 3: Reverse SHA-based encryption.
 * Reads the file, checks for the header "SHA:", then prompts for the password.
 * It computes the SHA256 digest of the password to recreate the key and XORs
 * each byte of the file (after the header) with the key.
 */
void decrypt_sha(const char *inputFile, const char *outputFile) {
    FILE *in = fopen(inputFile, "rb");
    if (!in) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }
    char header[HEADER_SIZE + 1] = {0};
    if (fread(header, 1, HEADER_SIZE, in) != HEADER_SIZE) {
        fprintf(stderr, "Error reading header\n");
        exit(EXIT_FAILURE);
    }
    if (strncmp(header, "SHA:", HEADER_SIZE) != 0) {
        fprintf(stderr, "File does not appear to be SHA-based encrypted\n");
        exit(EXIT_FAILURE);
    }

    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    long data_len = file_size - HEADER_SIZE;
    rewind(in);
    fseek(in, HEADER_SIZE, SEEK_SET);
    unsigned char *data = malloc(data_len);
    if (fread(data, 1, data_len, in) != (size_t)data_len) {
        fprintf(stderr, "Error reading data\n");
        exit(EXIT_FAILURE);
    }
    fclose(in);

    char password[128];
    printf("Enter password for SHA-based decryption: ");
    scanf("%127s", password);

    unsigned char key[32];
    SHA256((unsigned char*)password, strlen(password), key);

    for (long i = 0; i < data_len; i++) {
        data[i] ^= key[i % 32];
    }

    FILE *out = fopen(outputFile, "wb");
    if (!out) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }
    fwrite(data, 1, data_len, out);
    fclose(out);
    free(data);

    printf("SHA-based decryption completed. Output saved to %s\n", outputFile);
}

int main() {
    char inputFile[256], outputFile[256];
    printf("Enter encrypted file name: ");
    scanf("%255s", inputFile);
    printf("Enter output file name for decrypted content: ");
    scanf("%255s", outputFile);

    /* Read header from file to decide decryption method */
    FILE *in = fopen(inputFile, "rb");
    if (!in) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }
    char header[HEADER_SIZE + 1] = {0};
    if (fread(header, 1, HEADER_SIZE, in) != HEADER_SIZE) {
        fprintf(stderr, "Error reading header\n");
        exit(EXIT_FAILURE);
    }
    fclose(in);

    if (strncmp(header, "GSA:", HEADER_SIZE) == 0) {
        decrypt_gsa(inputFile, outputFile);
    } else if (strncmp(header, "AES:", HEADER_SIZE) == 0) {
        decrypt_aes(inputFile, outputFile);
    } else if (strncmp(header, "SHA:", HEADER_SIZE) == 0) {
        decrypt_sha(inputFile, outputFile);
    } else {
        printf("Unknown encryption method.\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}
