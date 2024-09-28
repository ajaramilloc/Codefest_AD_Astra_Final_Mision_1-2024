#ifndef HKDF_H
#define HKDF_H

#include <vector>
#include <string>

std::vector<unsigned char> HKDF_Extract(const std::vector<unsigned char> &salt, const std::vector<unsigned char> &inputKeyMaterial);
std::vector<unsigned char> HKDF_Expand(const std::vector<unsigned char> &prk, const std::vector<unsigned char> &info, size_t outputLength);
std::vector<unsigned char> HKDF(const std::vector<unsigned char> &salt, const std::vector<unsigned char> &inputKeyMaterial, const std::vector<unsigned char> &info, size_t outputLength);

#endif