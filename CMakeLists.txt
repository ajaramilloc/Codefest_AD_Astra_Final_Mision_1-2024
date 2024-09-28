cmake_minimum_required(VERSION 3.10)

# Nombre del proyecto
project(Codefest_Ad_Astra)

# Activar las advertencias por si OpenSSL no está disponible
find_package(OpenSSL REQUIRED)

# Incluir directorios
include_directories(CryptoLib/include)

# Archivos fuente para la librería CryptoLib
set(CRYPTO_SOURCES
    CryptoLib/src/decrypt.cpp
    CryptoLib/src/encrypt.cpp
    CryptoLib/src/hkdf.cpp
)

# Crear la librería CryptoLib
add_library(CryptoLib STATIC ${CRYPTO_SOURCES})

# Archivo principal main.cpp
add_executable(Codefest_AD_Astra_Final_Mision_1-2024 main.cpp)

# Enlazar la librería CryptoLib con el ejecutable
target_link_libraries(Codefest_AD_Astra_Final_Mision_1-2024 CryptoLib OpenSSL::SSL OpenSSL::Crypto)

# Configurar el nombre del binario y el directorio de salida (el directorio raíz del proyecto)
set_target_properties(Codefest_AD_Astra_Final_Mision_1-2024 PROPERTIES
    OUTPUT_NAME "main"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
)