#include "hkdf.h"  
#include <openssl/evp.h>  
#include <openssl/hmac.h> 
#include <string>         
#include <vector>         

// Función para realizar la parte de extracción de HKDF
// Argumentos:
// - salt: valor de sal (tipo std::vector<unsigned char>)
// - inputKeyMaterial: material clave inicial (tipo std::vector<unsigned char>)
// Devuelve: una pseudoclave raíz (PRK) de tipo std::vector<unsigned char>
std::vector<unsigned char> HKDF_Extract(const std::vector<unsigned char> &salt, const std::vector<unsigned char> &inputKeyMaterial)
{
    unsigned int len;
    std::vector<unsigned char> prk(EVP_MAX_MD_SIZE);  // Reserva espacio para la PRK
    // Realiza HMAC con SHA-256 usando el salt y el material clave inicial
    HMAC(EVP_sha256(), salt.data(), salt.size(), inputKeyMaterial.data(), inputKeyMaterial.size(), prk.data(), &len);
    prk.resize(len);  // Ajusta el tamaño de la PRK al tamaño real
    return prk;  // Devuelve la PRK
}

// Función para realizar la parte de expansión de HKDF
// Argumentos:
// - prk: pseudoclave raíz (tipo std::vector<unsigned char>)
// - info: información adicional utilizada en la expansión (tipo std::vector<unsigned char>)
// - outputLength: longitud de la clave de salida (tipo size_t)
// Devuelve: la clave de salida (OKM) de tipo std::vector<unsigned char>
std::vector<unsigned char> HKDF_Expand(const std::vector<unsigned char> &prk, const std::vector<unsigned char> &info, size_t outputLength)
{
    std::vector<unsigned char> okm;  // Vector para almacenar la clave de salida
    unsigned int hashLen = prk.size();  // Longitud del hash
    unsigned int n = (outputLength + hashLen - 1) / hashLen;  // Número de bloques necesarios

    std::vector<unsigned char> previous;  // Vector para almacenar el bloque anterior
    for (unsigned int i = 0; i < n; ++i)
    {
        std::vector<unsigned char> data(previous.begin(), previous.end());  // Copia el bloque anterior
        data.insert(data.end(), info.begin(), info.end());  // Añade la información adicional
        data.push_back(static_cast<unsigned char>(i + 1));  // Añade el contador de bloques

        previous.resize(hashLen);  // Ajusta el tamaño del vector previous
        unsigned int len;
        // Realiza HMAC con SHA-256 usando la PRK y los datos concatenados
        HMAC(EVP_sha256(), prk.data(), prk.size(), data.data(), data.size(), previous.data(), &len);
        previous.resize(len);  // Ajusta el tamaño de previous al tamaño real

        okm.insert(okm.end(), previous.begin(), previous.end());  // Añade el bloque al OKM
    }

    okm.resize(outputLength);  // Ajusta el tamaño del OKM al tamaño de salida deseado
    return okm;  // Devuelve el OKM
}

// Función para realizar la derivación de clave completa usando HKDF
// Argumentos:
// - salt: valor de sal (tipo std::vector<unsigned char>)
// - inputKeyMaterial: material clave inicial (tipo std::vector<unsigned char>)
// - info: información adicional utilizada en la expansión (tipo std::vector<unsigned char>)
// - outputLength: longitud de la clave de salida (tipo size_t)
// Devuelve: la clave derivada (OKM) de tipo std::vector<unsigned char>
std::vector<unsigned char> HKDF(const std::vector<unsigned char> &salt, const std::vector<unsigned char> &inputKeyMaterial, const std::vector<unsigned char> &info, size_t outputLength)
{
    std::vector<unsigned char> prk = HKDF_Extract(salt, inputKeyMaterial);  // Realiza la extracción y obtiene la PRK
    return HKDF_Expand(prk, info, outputLength);  // Realiza la expansión y devuelve la clave derivada (OKM)
}
