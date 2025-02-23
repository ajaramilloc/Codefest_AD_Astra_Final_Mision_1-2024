// Declaraciones de librerías usadas
#include <iostream>
#include <string>
#include <cstdlib>
#include "./CryptoLib/include/encrypt.h" // Importar la función de encriptación
#include "./CryptoLib/include/decrypt.h" // Importar la función de desencriptación

// Declaraciones de funciones
void encrypt(const std::string &input_path, const std::string &output_path);
void decrypt(const std::string &input_path, const std::string &output_path);

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cerr << "Uso: " << argv[0] << " <operation> <input_path> <output_path>" << std::endl;
        return 1;
    }

    std::string operation = argv[1];
    std::string input_path = argv[2];
    std::string output_path = argv[3];

    if (operation == "encrypt")
    {
        encrypt(input_path, output_path);
    }
    else if (operation == "decrypt")
    {
        decrypt(input_path, output_path);
    }
    else
    {
        std::cerr << "Operación no válida: " << operation << std::endl;
        return 1;
    }

    return 0;
}

void encrypt(const std::string &input_path, const std::string &output_path)
{
    std::cout << "input_path=" << input_path << std::endl;
    std::cout << "output_path=" << output_path << std::endl;

    // Llamada a la función de encriptación
    encrypt_algorithm(input_path, output_path);
    std::cout << "Encrypted image" << std::endl;
}

void decrypt(const std::string &input_path, const std::string &output_path)
{
    std::cout << "input_path=" << input_path << std::endl;
    std::cout << "output_path=" << output_path << std::endl;

    // Llamada a la función de desencriptación
    decrypt_algorithm(input_path, output_path);
    std::cout << "Decrypted image" << std::endl;
}
