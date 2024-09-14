# AES Encryption/Decryption Example using OpenSSL

## Overview

This project demonstrates how to encrypt and decrypt multiple plaintext messages using AES-256 in CBC mode with OpenSSL's EVP API. The program generates an AES encryption key and an initialization vector (IV), encrypts a series of plaintext messages, and then decrypts them back to their original form. The encryption and decryption processes are chunked to handle large ciphertexts, which is useful for data streaming or large files.

## Features

- **AES-256-CBC Encryption**: Encrypts data using 256-bit AES in CBC (Cipher Block Chaining) mode.
- **Chunked Decryption**: Decrypts data in chunks to handle large ciphertexts efficiently.
- **PKCS#7 Padding**: Automatically handles padding during encryption and decryption.
- **Hexadecimal Data Representation**: Prints key, IV, plaintext, ciphertext, and decrypted text in hexadecimal format for better readability.

## Prerequisites

- **OpenSSL**: This program requires the OpenSSL library to compile and run. Make sure OpenSSL is installed on your system.
  
  - On Ubuntu/Debian-based systems, you can install it using:
    ```bash
    sudo apt-get install libssl-dev
    ```

## Files

### 1. `main.c`

This is the main source file containing the following components:

- **Fixed Key and Random IV Generation**: Uses a fixed 256-bit AES key and randomly generates a 16-byte initialization vector (IV).
- **AES Encryption**: Encrypts multiple plaintext messages and outputs the resulting ciphertext.
- **Chunked AES Decryption**: Decrypts the ciphertext in chunks and reconstructs the original plaintext.
- **Utility Function (`print_data`)**: Prints the fixed key, randomly generated IV, plaintext, ciphertext, and decrypted text in a formatted hexadecimal string.

### 2. `README.md`

This file contains an overview of the project and instructions on how to compile and run the program.

## How to Compile

Make sure you have OpenSSL installed and then use the following command to compile the program:

```bash
mkdir build
cd build
cmake ..
make
./aes_example

