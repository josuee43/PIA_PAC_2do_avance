// =============================================================================
// modules/sha256.h — Implementación pura en C++17 de SHA-256 (FIPS 180-4).
// -----------------------------------------------------------------------------
// Sin dependencias externas (no OpenSSL). Pensada para ser fácilmente legible
// en un análisis estático: las constantes K[64] y H0[8] aparecen embebidas y
// son una huella reconocible en Ghidra/Radare2.
// =============================================================================
#ifndef EDUSEC_MODULES_SHA256_H
#define EDUSEC_MODULES_SHA256_H

#include <array>
#include <cstdint>
#include <cstddef>
#include <string>

namespace edusec::sha256 {

// Estado incremental para hashear flujos / archivos grandes sin cargarlos en RAM.
class Context {
   public:
    Context();
    void update(const void* data, std::size_t len);
    std::array<std::uint8_t, 32> finalize();          // 32 bytes raw
    static std::string to_hex(const std::array<std::uint8_t, 32>& digest);

   private:
    void process_block(const std::uint8_t block[64]);

    std::array<std::uint32_t, 8> h_;
    std::array<std::uint8_t, 64> buffer_;
    std::size_t buffer_len_ = 0;
    std::uint64_t bit_count_ = 0;
};

// Atajos.
std::string hash_string(const std::string& s);
std::string hash_bytes(const void* data, std::size_t len);

}  // namespace edusec::sha256

#endif  // EDUSEC_MODULES_SHA256_H
