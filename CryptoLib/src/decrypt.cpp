#include "decrypt.h"
#include "hkdf.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <vector>

// Hash estático utilizado como sal para HKDF
const unsigned char static_hash[32] = {
    0xb2, 0xf6, 0xc2, 0x3f, 0x9a, 0xc1, 0xe3, 0xb0,
    0xf5, 0xe7, 0xa5, 0x65, 0x9f, 0x91, 0x56, 0x3e,
    0x1c, 0x75, 0x92, 0x6a, 0x27, 0x61, 0x27, 0xe6,
    0x48, 0xef, 0xbb, 0xc0, 0xc7, 0xad, 0x52, 0xaa};

// Función para manejar errores de OpenSSL
inline void handleErrors()
{
    ERR_print_errors_fp(stderr); // Imprime los errores en la salida de errores estándar
    abort();                     // Termina la ejecución del programa
}

// Función principal de desencriptación
// Argumentos:
// - input_path: ruta del archivo de entrada a desencriptar (tipo std::string)
// - output_path: ruta del archivo de salida donde se guardará el contenido desencriptado (tipo std::string)
void decrypt_algorithm(const std::string &input_path, const std::string &output_path)
{
    // Abre el archivo de entrada en modo binario
    std::ifstream input_file(input_path, std::ios::binary);
    // Abre el archivo de salida en modo binario
    std::ofstream output_file(output_path, std::ios::binary);

    // Verifica si los archivos se abrieron correctamente
    if (!input_file.is_open() || !output_file.is_open())
    {
        std::cerr << "Error opening file." << std::endl; // Muestra un mensaje de error si no se pudieron abrir los archivos
        return;
    }

    // Lee el nonce del archivo de entrada
    std::vector<unsigned char> nonce(16);
    input_file.read(reinterpret_cast<char *>(nonce.data()), nonce.size());

    // Configuración para HKDF
    std::vector<unsigned char> salt(static_hash, static_hash + sizeof(static_hash));               // Utiliza el hash estático como sal
    std::vector<unsigned char> ikm = {'C', 'o', 'd', 'e', 'f', 'e', 's', 't', '2', '0', '2', '4'}; // Material clave inicial
    size_t key_len = 16;                                                                           // Longitud de la clave
    std::vector<unsigned char> key = HKDF(salt, ikm, nonce, key_len);                              // Genera la clave usando HKDF

    // Inicializa el contexto de cifrado
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors(); // Maneja errores si no se pudo crear el contexto

    const EVP_CIPHER *cipher = EVP_aes_128_ctr(); // Selecciona el cifrado AES-128-CTR
    unsigned char iv[16] = {0};                   // Vector de inicialización (IV) inicializado a 0

    // Copia el nonce en el IV para usarlo en el descifrado
    std::copy(nonce.begin(), nonce.end(), iv);

    // Inicializa el contexto de desencriptación
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv) != 1)
        handleErrors(); // Maneja errores si la inicialización falla

    const std::size_t block_size = 16;                              // Tamaño del bloque para el cifrado AES
    const std::size_t chunk_size = 1024 * 1024;                     // Tamaño del fragmento de lectura (1 MB)
    std::vector<unsigned char> buffer(chunk_size);                  // Buffer para la lectura del archivo
    std::vector<unsigned char> out_buffer(chunk_size + block_size); // Buffer para la salida del desencriptado
    int out_len;                                                    // Variable para almacenar la longitud de la salida

    // Bucle para leer y desencriptar el archivo por fragmentos
    while (!input_file.eof())
    {
        input_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size()); // Lee un fragmento del archivo
        std::streamsize bytes_read = input_file.gcount();                        // Obtiene el número de bytes leídos

        // Desencripta el fragmento leído
        if (EVP_DecryptUpdate(ctx, out_buffer.data(), &out_len, buffer.data(), bytes_read) != 1)
            handleErrors(); // Maneja errores si la desencriptación falla

        // Escribe el fragmento desencriptado en el archivo de salida
        output_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
    }

    // Finaliza la desencriptación y escribe cualquier dato restante
    if (EVP_DecryptFinal_ex(ctx, out_buffer.data(), &out_len) != 1)
        handleErrors(); // Maneja errores si la finalización de la desencriptación falla

    // Escribe el último fragmento desencriptado en el archivo de salida
    output_file.write(reinterpret_cast<char *>(out_buffer.data()), out_len);

    // Libera el contexto de cifrado
    EVP_CIPHER_CTX_free(ctx);
    // Cierra los archivos de entrada y salida
    input_file.close();
    output_file.close();

    // Muestra un mensaje indicando que el archivo fue procesado (desencriptado)
    std::cout << "Processed (decrypted) file" << std::endl;
}
