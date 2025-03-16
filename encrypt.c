/* encryption.c
 *
 * Implements three encryption methods:
 * 1. Linux command pipeline using cat, grep, sed, and awk.
 * 2. AES-256-CBC encryption using OpenSSL.
 * 3. “SHA-based” encryption by XOR-ing with the SHA256 digest of a password.
 *
 * Compile with: gcc encryption.c -o encrypt -lcrypto
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define HEADER_SIZE 4
#define IV_SIZE 16

/* Print OpenSSL errors and abort */
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/* Method 1: Encrypt using Linux commands.
 * This builds a pipeline that:
 *   - Uses cat to read the file,
 *   - Filters non-empty lines with grep,
 *   - Uses sed to transliterate A→B, B→C, …, z→a (for letters only),
 *   - Uses awk to prefix the output with "GSA:".
 */
void encrypt_gsa(const char *inputFile, const char *outputFile) {
    char command[1024];
    snprintf(command, sizeof(command),
        "cat %s | grep . | sed 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz/BCDEFGHIJKLMNOPQRSTUVWXYZAbcdefghijklmnopqrstuvwxyza/' | awk 'BEGIN{ORS=\"\"; print \"GSA:\"} {print $0 \"\\n\"}' > %s",
        inputFile, outputFile);
    if (system(command) == -1) {
        perror("Error executing system command");
        exit(EXIT_FAILURE);
    }
}

/* Method 2: AES-256-CBC encryption using OpenSSL.
 * The function reads the entire input file, asks the user for a password,
 * derives a 256-bit key by taking SHA256(password), generates a random IV,
 * encrypts the data using the EVP API, and writes out:
 *   "AES:" | IV (16 bytes) | ciphertext.
 */
void encrypt_aes(const char *inputFile, const char *outputFile) {
    FILE *in = fopen(inputFile, "rb");
    if (!in) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }
    fseek(in, 0, SEEK_END);
    long plaintext_len = ftell(in);
    rewind(in);
    unsigned char *plaintext = malloc(plaintext_len);
    if (fread(plaintext, 1, plaintext_len, in) != (size_t)plaintext_len) {
        perror("Error reading input file");
        fclose(in);
        exit(EXIT_FAILURE);
    }
    fclose(in);

    char password[128];
    printf("Enter password for AES encryption: ");
    scanf("%127s", password);

    /* Derive a 256-bit key from the password using SHA256 */
    unsigned char key[32];
    SHA256((unsigned char*)password, strlen(password), key);

    /* Generate a random 128-bit IV */
    unsigned char iv[IV_SIZE];
    if (!RAND_bytes(iv, IV_SIZE)) {
        fprintf(stderr, "Error generating IV\n");
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    int ciphertext_len = plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc());
    unsigned char *ciphertext = malloc(ciphertext_len);
    int len, total_len = 0;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    total_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    total_len += len;

    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);

    FILE *out = fopen(outputFile, "wb");
    if (!out) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }
    /* Write header, then IV, then ciphertext */
    fwrite("AES:", 1, HEADER_SIZE, out);
    fwrite(iv, 1, IV_SIZE, out);
    fwrite(ciphertext, 1, total_len, out);
    fclose(out);
    free(ciphertext);

    printf("AES encryption completed. Output saved to %s\n", outputFile);
}

/* Method 3: “SHA-based” encryption.
 * This function computes SHA256 of a user-provided password to obtain a 32-byte key,
 * then reads the input file and XORs every byte with the key (repeating the key as needed).
 * The output file is written with the header "SHA:" followed by the transformed data.
 */
void encrypt_sha(const char *inputFile, const char *outputFile) {
    FILE *in = fopen(inputFile, "rb");
    if (!in) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }
    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    rewind(in);
    unsigned char *buffer = malloc(file_size);
    if (fread(buffer, 1, file_size, in) != (size_t)file_size) {
        perror("Error reading input file");
        fclose(in);
        exit(EXIT_FAILURE);
    }
    fclose(in);

    char password[128];
    printf("Enter password for SHA-based encryption: ");
    scanf("%127s", password);

    unsigned char key[32];
    SHA256((unsigned char*)password, strlen(password), key);

    for (long i = 0; i < file_size; i++) {
        buffer[i] ^= key[i % 32];
    }

    FILE *out = fopen(outputFile, "wb");
    if (!out) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }
    fwrite("SHA:", 1, HEADER_SIZE, out);
    fwrite(buffer, 1, file_size, out);
    fclose(out);
    free(buffer);

    printf("SHA-based encryption completed. Output saved to %s\n", outputFile);
}

int main() {
    int option;
    char inputFile[256], outputFile[256];

    printf("Enter input file name: ");
    scanf("%255s", inputFile);
    printf("Enter output file name: ");
    scanf("%255s", outputFile);

    printf("\nChoose encryption method:\n");
    printf("1. Linux command encryption (using cat, grep, sed, awk)\n");
    printf("2. AES encryption (using OpenSSL)\n");
    printf("3. SHA-based encryption (XOR with SHA256 digest)\n");
    printf("Enter option (1-3): ");
    scanf("%d", &option);

    switch (option) {
        case 1:
            encrypt_gsa(inputFile, outputFile);
            break;
        case 2:
            encrypt_aes(inputFile, outputFile);
            break;
        case 3:
            encrypt_sha(inputFile, outputFile);
            break;
        default:
            printf("Invalid option.\n");
            exit(EXIT_FAILURE);
    }
    return 0;
}
