# Encryption and Decryption Tools

This repository contains two C programs that implement three methods for encrypting and decrypting files.

## Overview

The project implements three encryption/decryption methods:

1. **Linux Command Pipeline Encryption**  
   - **Encryption:** Uses a pipeline of Linux commands (`cat`, `grep`, `sed`, and `awk`) to transform the file contents by transliterating letters and adding a "GSA:" header.
   - **Decryption:** Reverses the process using `tail` and `sed` to restore the original text.

2. **AES-256-CBC Encryption (using OpenSSL)**  
   - **Encryption:** Reads an input file, derives a 256-bit key from a user-provided password (using SHA256), generates a random IV, and encrypts the data using AES-256-CBC. The output file contains a header ("AES:"), the IV, and the ciphertext.
   - **Decryption:** Extracts the header, IV, and ciphertext from the file, then uses the same password-derived key to decrypt the file.

3. **SHA-Based Encryption (XOR with SHA256 Digest)**  
   - **Encryption:** Computes a SHA256 digest of a user-provided password to generate a 32-byte key, then XORs each byte of the input file with the key (cycling through as needed). The output file is prefixed with a header ("SHA:").
   - **Decryption:** Reads the header and applies the XOR process with the same SHA256-derived key to restore the original data.

## Files

- **encryption.c:** Contains the code for all three encryption methods.
- **decryption.c:** Contains the code for the corresponding decryption methods.
- **.github/workflows/build.yml:** (Optional) GitHub Actions workflow file to automatically compile the code on every push.

## Requirements

- **Compiler:** GCC
- **Libraries:** OpenSSL (e.g., install `libssl-dev` on Ubuntu)
- **Environment:** Linux or any Unix-like system with standard utilities (`cat`, `grep`, `sed`, `awk`, `tail`)

## Compilation

To compile the programs locally, open a terminal in the repository directory and run:

```bash
gcc encryption.c -o encrypt -lcrypto
gcc decryption.c -o decrypt -lcrypto
