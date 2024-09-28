#include "encrypt.h"
#include "hkdf.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <vector>

// Función para manejar errores de OpenSSL
inline void handleErrors()
{
    ERR_print_errors_fp(stderr); // Imprime los errores en la salida de errores estándar
    abort();                     // Termina la ejecución del programa
}

// Función principal de encriptación
// Argumentos:
// - input_path: ruta del archivo de entrada a encriptar (tipo std::string)
// - output_path: ruta del archivo de salida donde se guardará el contenido encriptado (tipo std::string)
void encrypt_algorithm(const std::string &input_path, const std::string &output_path)
{
    // Abre el archivo de entrada en modo binario
    std::ifstream input_file(input_path, std::ios::binary);
    // Abre el archivo de salida en modo binario
    std::ofstream output_file(output_path, std::ios::binary);

    // Verifica si los archivos se abrieron correctamente
    if (!input_file.is_open() || !output_file.is_open())
    {
        std::cerr << "Error opening file." << std::endl;
        return;
    }

    // Genera una sal aleatoria (32 bytes)
    std::vector<unsigned char> salt(32);
    if (!RAND_bytes(salt.data(), salt.size()))
    {
        handleErrors();
    }

    // Genera un nonce aleatorio (16 bytes)
    std::vector<unsigned char> nonce(16);
    if (!RAND_bytes(nonce.data(), nonce.size()))
    {
        handleErrors();
    }

    // Material clave inicial y longitud de la clave
    std::vector<unsigned char> ikm = {'C', 'o', 'd', 'e', 'f', 'e', 's', 't', '2', '0', '2', '4'};
    size_t key_len = 16;

    // Deriva la clave utilizando HKDF con la sal dinámica y el nonce
    std::vector<unsigned char> key = HKDF(salt, ikm, nonce, key_len);

    // Inicializa el contexto de encriptación
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors();

    const EVP_CIPHER *cipher = EVP_aes_128_ctr();
    unsigned char iv[16] = {0};

    // Copia el nonce en el IV
    std::copy(nonce.begin(), nonce.end(), iv);

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv) != 1)
        handleErrors();

    const std::size_t block_size = 16;
    const std::size_t chunk_size = 64 * 1024;
    std::vector<unsigned char> buffer(chunk_size);
    std::vector<unsigned char> out_buffer(chunk_size + block_size);
    int out_len;

    // *** Escribe la sal y el nonce en el archivo de salida ***
    // Escribe la sal (32 bytes)
    output_file.write(reinterpret_cast<char *>(salt.data()), salt.size());
    // Escribe el nonce (16 bytes)
    output_file.write(reinterpret_cast<char *>(nonce.data()), nonce.size());

    // Bucle para leer y encriptar el archivo por fragmentos
    while (!input_file.eof())
    {
        input_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
        std::streamsize bytes_read = input_file.gcount();

        if (EVP_EncryptUpdate(ctx, out_buffer.data(), &out_len, buffer.data(), bytes_read) != 1)
            handleErrors();

        output_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
    }

    if (EVP_EncryptFinal_ex(ctx, out_buffer.data(), &out_len) != 1)
        handleErrors();

    output_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);

    EVP_CIPHER_CTX_free(ctx);
    input_file.close();
    output_file.close();

    std::cout << "Processed (encrypted) file with dynamic salt" << std::endl;
}
