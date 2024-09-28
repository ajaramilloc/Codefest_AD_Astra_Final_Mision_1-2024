# Codefest Ad Astra

This is the Quantum Commandos repository, for the Codefest Ad Astra 2024 challenge

## Table of Contents

1. [Project Overview](#project-overview)
2. [File Structure](#file-structure)
3. [Usage](#usage)
4. [Encryption](#encryption-process)
5. [Decryptionn](#decryption-process)
6. [HDKF](#hdkf-function)
7. [Video](#video)
8. [References](#references)

## Project Overview

Codefest Ad Astra is a cryptographic library and application designed to perform encryption and decryption of files using advanced cryptographic algorithms. The library is built using C++ and OpenSSL to ensure robust and secure cryptographic operations.

## File Structure

The project is organized as follows:

```
Codefest_Ad_Astra/

├── src/CryptoLib/
│   │
│   ├── include/
│   │   ├── decrypt.h
│   │   ├── encrypt.h
│   │   └── hkdf.h
│   │
│   └── src/
│       ├── decrypt.cpp
│       ├── encrypt.cpp
│       └── hkdf.cpp
│
├── main.cpp
│
│── CMake
│
├── tests/
│   ├── output/
│   ├── encrypted/
│   ├── input/
|   |── run_tests.bat
│
└── README.md
```

- **main_lib.cpp**: The main application file.
- **CryptoLib/include/**: Header files for the cryptographic library.
- **CryptoLib/src/**: Implementation files for the cryptographic library.
- **tests/input**: The original photos before encrypted.
- **tests/encrypted**: The photos encrypted (may be shown as corrupted archives, this is because the division with chunks).
- **tests/output**: The photos after decrypted.

## Usage

### Linux Compilation

To compile and run the project in Linux, follow these steps:

compile:
```
cd build
cmake ..
cd ..
```
encrypt:
```
./main encrypt ./tests/input/image.tif ./tests/encrypted/image.tif
```
decrypt:
```
./main decrypt ./tests/encrypted/image.tif ./tests/output/image.tif
```
clean all files generated:
```
make clean
```

**Note**: Replace image.tif with the desired image.

### Windows Compilation

To compile and run the project in Windows, follow these steps:

compile:
```
g++ -o ./main ./main.cpp ./CryptoLib/src/encrypt.cpp ./CryptoLib/src/decrypt.cpp ./CryptoLib/src/hkdf.cpp -I./CryptoLib/include -lssl -lcrypto
```
encrypt:
```
./main encrypt ./tests/input/image.tif ./tests/encrypted/image.tif
```
decrypt:
```
./main decrypt ./tests/encrypted/image.tif ./tests/output/image.tif
```

**Note**: Replace image.tif with the desired image.

## Encryption Process

The encryption process is designed to securely encrypt files using the AES-128-CBC algorithm and dynamically generated keys through HKDF (HMAC-based Key Derivation Function). Below is the detailed workflow of the `encrypt_algorithm` function:

1. **File Handling**: The function opens the input file to be encrypted and the output file where the encrypted content will be stored.

   ```cpp
   std::ifstream input_file(input_path, std::ios::binary);
   std::ofstream output_file(output_path, std::ios::binary);
   ```

2. **Nonce Generation**: A random nonce (Number used once) is generated using OpenSSL's `RAND_bytes` function.

   ```cpp
   std::vector<unsigned char> nonce(16);
   if (!RAND_bytes(nonce.data(), nonce.size())) {
       handleErrors();
   }
   ```

3. **Salt Generation**: A random salt (32 bytes) is generated using OpenSSL's RAND_bytes function, ensuring that each encryption session is unique.

   ```cpp
   std::vector<unsigned char> salt(32);
   if (!RAND_bytes(salt.data(), salt.size())) {
       handleErrors();
   }
   ```

4. **Key Derivation using HKDF**:

   - A static hash is used as salt.
   - An initial key material (`ikm`) is defined.
   - HKDF is used to derive a cryptographic key from the salt, ikm, and nonce.

   ```cpp
   std::vector<unsigned char> salt(static_hash, static_hash + sizeof(static_hash));
   std::vector<unsigned char> ikm = {'C', 'o', 'd', 'e', 'f', 'e', 's', 't', '2', '0', '2', '4'};
   size_t key_len = 16;
   std::vector<unsigned char> key = HKDF(salt, ikm, nonce, key_len);
   ```

5. **Encryption Setup**: The encryption context is initialized with the derived key and an IV (Initialization Vector) of zeros.

   ```cpp
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   const EVP_CIPHER *cipher = EVP_aes_128_cbc();
   unsigned char iv[16] = {0};
   if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv) != 1)
       handleErrors();
   ```

6. **Chunk-based Encryption**:

   - The input file is read in chunks.
   - Each chunk is encrypted and written to the output file.

   ```cpp
   const std::size_t chunk_size = 1024 * 1024;
   std::vector<unsigned char> buffer(chunk_size);
   std::vector<unsigned char> out_buffer(chunk_size + 16);
   int out_len;

   output_file.write(reinterpret_cast<char *>(nonce.data()), nonce.size());

   while (!input_file.eof()) {
       input_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
       std::streamsize bytes_read = input_file.gcount();
       if (EVP_EncryptUpdate(ctx, out_buffer.data(), &out_len, buffer.data(), bytes_read) != 1)
           handleErrors();
       output_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
   }

   if (EVP_EncryptFinal_ex(ctx, out_buffer.data(), &out_len) != 1)
       handleErrors();
   output_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
   ```

7. **Cleanup**: The encryption context is freed and the files are closed.
   ```cpp
   EVP_CIPHER_CTX_free(ctx);
   input_file.close();
   output_file.close();
   ```

## Decryption Process

The decryption process reverses the encryption steps to retrieve the original file content. Below is the detailed workflow of the `decrypt_algorithm` function:

1. **File Handling**: The function opens the input file to be decrypted and the output file where the decrypted content will be stored.

   ```cpp
   std::ifstream input_file(input_path, std::ios::binary);
   std::ofstream output_file(output_path, std::ios::binary);
   ```

2. **Salt and Nonce Extraction**: The nonce is read from the beginning of the encrypted input file.

   ```cpp
   std::vector<unsigned char> salt(32);
   input_file.read(reinterpret_cast<char *>(salt.data()), salt.size());
   
   std::vector<unsigned char> nonce(16);
   input_file.read(reinterpret_cast<char *>(nonce.data()), nonce.size());
   ```

3. **Key Derivation using HKDF**: The same key derivation steps as in encryption are performed to retrieve the cryptographic key.

   ```cpp
   std::vector<unsigned char> salt(static_hash, static_hash + sizeof(static_hash));
   std::vector<unsigned char> ikm = {'C', 'o', 'd', 'e', 'f', 'e', 's', 't', '2', '0', '2', '4'};
   size_t key_len = 16;
   std::vector<unsigned char> key = HKDF(salt, ikm, nonce, key_len);
   ```

4. **Decryption Setup**: The decryption context is initialized with the derived key and an IV of zeros.

   ```cpp
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   const EVP_CIPHER *cipher = EVP_aes_128_cbc();
   unsigned char iv[16] = {0};
   if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv) != 1)
       handleErrors();
   ```

5. **Chunk-based Decryption**:

   - The encrypted file is read in chunks.
   - Each chunk is decrypted and written to the output file.

   ```cpp
   const std::size_t chunk_size = 1024 * 1024;
   std::vector<unsigned char> buffer(chunk_size);
   std::vector<unsigned char> out_buffer(chunk_size + 16);
   int out_len;

   while (!input_file.eof()) {
       input_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
       std::streamsize bytes_read = input_file.gcount();
       if (EVP_DecryptUpdate(ctx, out_buffer.data(), &out_len, buffer.data(), bytes_read) != 1)
           handleErrors();
       output_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
   }

   if (EVP_DecryptFinal_ex(ctx, out_buffer.data(), &out_len) != 1)
       handleErrors();
   output_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
   ```

6. **Cleanup**: The decryption context is freed and the files are closed.
   ```cpp
   EVP_CIPHER_CTX_free(ctx);
   input_file.close();
   output_file.close();
   ```

# HKDF Function

HKDF (HMAC-based Key Derivation Function) is used to generate dynamic cryptographic keys. It consists of two main steps: extraction and expansion.

![image](https://github.com/user-attachments/assets/9ed5c431-4aeb-4952-91b5-030a19aae751)
From: https://asecuritysite.com/hash/HKDF

## HKDF_Extract

Extracts a pseudorandom key (PRK) from the input key material and salt.

```cpp
std::vector<unsigned char> HKDF_Extract(const std::vector<unsigned char> &salt, const std::vector<unsigned char> &inputKeyMaterial) {
    unsigned int len;
    std::vector<unsigned char> prk(EVP_MAX_MD_SIZE);
    HMAC(EVP_sha256(), salt.data(), salt.size(), inputKeyMaterial.data(), inputKeyMaterial.size(), prk.data(), &len);
    prk.resize(len);
    return prk;
}
```

## HKDF_Expand

Expands the PRK into an output key material (OKM) using additional context information.

```cpp
std::vector<unsigned char> HKDF_Expand(const std::vector<unsigned char> &prk, const std::vector<unsigned char> &info, size_t outputLength) {
    std::vector<unsigned char> okm;
    unsigned int hashLen = prk.size();
    unsigned int n = (outputLength + hashLen - 1) / hashLen;
    std::vector<unsigned char> previous;

    for (unsigned int i = 0; i < n; ++i) {
        std::vector<unsigned char> data(previous.begin(), previous.end());
        data.insert(data.end(), info.begin(), info.end());
        data.push_back(static_cast<unsigned char>(i + 1));
        previous.resize(hashLen);
        unsigned int len;
        HMAC(EVP_sha256(), prk.data(), prk.size(), data.data(), data.size(), previous.data(), &len);
        previous.resize(len);
        okm.insert(okm.end(), previous.begin(), previous.end());
    }

    okm.resize(outputLength);
    return okm;
}
```

## HKDF

Combines the extraction and expansion steps to derive a key from the input key material, salt, and context information.

```cpp
std::vector<unsigned char> HKDF(const std::vector<unsigned char> &salt, const std::vector<unsigned char> &inputKeyMaterial, const std::vector<unsigned char> &info, size_t outputLength) {
    std::vector<unsigned char> prk = HKDF_Extract(salt, inputKeyMaterial);
    return HKDF_Expand(prk, info, outputLength);
}
```

## Libraries Used

- **iostream**: Provides functionalities for standard input and output. It is used to display messages on the console and handle user input.  
  **Source**: C++ Standard Library.  
  **License**: No specific license applies as it is part of the C++ language standard, governed by the ISO C++ specification.

- **string**: Offers support for string manipulation. It is essential for managing file paths and string operations in the code.  
  **Source**: C++ Standard Library.  
  **License**: Part of the C++ language standard and regulated by the ISO C++ specification.

- **cstdlib**: Includes functions for performing general-purpose operations, such as dynamic memory management and random number generation. In this project, it is primarily used to handle program termination in case of errors.  
  **Source**: C++ Standard Library.  
  **License**: No specific license, being part of the ISO C++ standard.

- **openssl/evp.h**: Part of the OpenSSL library, it provides a high-level interface for cryptographic functions. It is used to initialize and manage encryption and decryption contexts, such as AES-128-CTR algorithms.  
  **Source**: OpenSSL Library.  
  **License**: OpenSSL License and Apache License 2.0. Users can choose between these two licenses.

- **openssl/hmac.h**: Provides functions for generating HMACs. It is crucial for implementing HKDF, which is used to derive secure cryptographic keys.  
  **Source**: OpenSSL Library.  
  **License**: Available under the OpenSSL License and Apache License 2.0.

- **openssl/err.h**: Enables management and reporting of OpenSSL-specific errors. It is used to capture and display errors in cryptographic operations, aiding in debugging and safely handling failures.  
  **Source**: OpenSSL Library.  
  **License**: OpenSSL License and Apache License 2.0.

- **openssl/rand.h**: Provides functions for generating high-quality random numbers, essential for creating encrypted nonces. It ensures that generated numbers are sufficiently random to maintain cryptographic security.  
  **Source**: OpenSSL Library.  
  **License**: OpenSSL License and Apache License 2.0.

- **fstream**: Provides functions for reading from and writing to files. It is used to handle input and output of binary data during encryption and decryption processes.  
  **Source**: C++ Standard Library.  
  **License**: Part of the C++ language standard according to the ISO C++ specification.

- **vector**: Part of the C++ Standard Library, it offers a dynamic array data structure. It is used to store variable-length data, such as data buffers during encryption/decryption and managing derived keys.  
  **Source**: C++ Standard Library.  
  **License**: No specific license, regulated by the ISO C++ specification.


## Video

Ups

## References

1. Moody, B. (n.d.). HMAC-based Extract-and-Expand Key Derivation Function (HKDF). Retrieved from https://asecuritysite.com/hash/HKDF
2. OpenSSL. (n.d.). OpenSSL: Cryptography and SSL/TLS toolkit. Retrieved from https://www.openssl.org/
3. Wikipedia. (2023). Advanced Encryption Standard. Retrieved from https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
4. Krawczyk, H., & Eronen, P. (2010). HMAC-based Extract-and-Expand Key Derivation Function (HKDF) (RFC 5869). Retrieved from https://tools.ietf.org/html/rfc5869
5. Wikipedia. (2023). HMAC. Retrieved from https://en.wikipedia.org/wiki/HMAC
6. Wikipedia. (2023). SHA-2. Retrieved from https://en.wikipedia.org/wiki/SHA-2
7. OpenSSL. (n.d.). EVP_EncryptInit_ex - OpenSSL [Manual]. Retrieved from https://www.openssl.org/docs/man1.1.1/man3/EVP_EncryptInit.html
8. OpenSSL. (n.d.). RAND_bytes - OpenSSL [Manual]. Retrieved from https://www.openssl.org/docs/man1.1.1/man3/RAND_bytes.html
9. Wikipedia. (2023). Initialization Vector. Retrieved from https://en.wikipedia.org/wiki/Initialization_vector
