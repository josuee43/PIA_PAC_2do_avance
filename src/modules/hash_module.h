// =============================================================================
// modules/hash_module.h — Módulo de hashing (FNV-1a/32 + SHA-256)
// -----------------------------------------------------------------------------
// FNV-1a/32 se conserva como ejemplo de hash no criptográfico, útil para el
// módulo de fuerza bruta como referencia rápida. SHA-256 (FIPS 180-4) se
// implementa en C++ puro en sha256.{h,cpp} y se expone aquí como segundo
// algoritmo del subcomando `hash`.
// =============================================================================
#ifndef EDUSEC_MODULES_HASH_MODULE_H
#define EDUSEC_MODULES_HASH_MODULE_H

#include <cstdint>
#include <string>
#include <vector>

namespace edusec::hash_module {

// Punto de entrada del subcomando `hash`.
int run(const std::vector<std::string>& args);

// Helpers expuestos para reutilización (p. ej. bruteforce_module).
std::uint32_t fnv1a_32(const void* data, std::size_t len);
std::string   fnv1a_32_hex(const std::string& s);
std::string   to_hex_u32(std::uint32_t value);

}  // namespace edusec::hash_module

#endif  // EDUSEC_MODULES_HASH_MODULE_H
