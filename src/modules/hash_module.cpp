// =============================================================================
// modules/hash_module.cpp — FNV-1a/32 + SHA-256 sobre cadena o archivo.
// -----------------------------------------------------------------------------
// Selección de algoritmo: --algo fnv  (default)  |  --algo sha256
// Entrada:                --string <texto>       |  --file <ruta>
// =============================================================================
#include "modules/hash_module.h"
#include "modules/sha256.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace edusec::hash_module {

namespace {
constexpr std::uint32_t kFnvOffset = 0x811C9DC5u;
constexpr std::uint32_t kFnvPrime  = 0x01000193u;
}  // namespace

std::uint32_t fnv1a_32(const void* data, std::size_t len) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::uint32_t hash = kFnvOffset;
    for (std::size_t i = 0; i < len; ++i) {
        hash ^= bytes[i];
        hash *= kFnvPrime;
    }
    return hash;
}

std::string to_hex_u32(std::uint32_t value) {
    std::ostringstream oss;
    oss << std::hex << std::setw(8) << std::setfill('0') << value;
    return oss.str();
}

std::string fnv1a_32_hex(const std::string& s) {
    return to_hex_u32(fnv1a_32(s.data(), s.size()));
}

namespace {

enum class Algo { Fnv, Sha256 };

int hash_string_fnv(const std::string& text) {
    std::cout << "FNV1a-32(string) = 0x"
              << to_hex_u32(fnv1a_32(text.data(), text.size())) << '\n';
    return 0;
}

int hash_string_sha(const std::string& text) {
    std::cout << "SHA-256(string)  = " << edusec::sha256::hash_string(text) << '\n';
    return 0;
}

int hash_file_fnv(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "[!] No se pudo abrir: " << path << '\n';
        return 1;
    }

    std::uint32_t hash = kFnvOffset;
    char buffer[4096];
    std::size_t total = 0;
    while (in.read(buffer, sizeof(buffer)) || in.gcount() > 0) {
        const auto got = static_cast<std::size_t>(in.gcount());
        for (std::size_t i = 0; i < got; ++i) {
            hash ^= static_cast<std::uint8_t>(buffer[i]);
            hash *= kFnvPrime;
        }
        total += got;
    }
    std::cout << "FNV1a-32(file)   = 0x" << to_hex_u32(hash)
              << "  (" << total << " bytes leídos: " << path << ")\n";
    return 0;
}

int hash_file_sha(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "[!] No se pudo abrir: " << path << '\n';
        return 1;
    }
    edusec::sha256::Context ctx;
    char buffer[4096];
    std::size_t total = 0;
    while (in.read(buffer, sizeof(buffer)) || in.gcount() > 0) {
        const auto got = static_cast<std::size_t>(in.gcount());
        ctx.update(buffer, got);
        total += got;
    }
    std::cout << "SHA-256(file)    = "
              << edusec::sha256::Context::to_hex(ctx.finalize())
              << "  (" << total << " bytes: " << path << ")\n";
    return 0;
}

}  // namespace

int run(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Uso: hash [--algo fnv|sha256] --string <texto> | --file <ruta>\n";
        return 2;
    }

    Algo algo = Algo::Fnv;
    std::string input_flag, input_value;

    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (a == "--algo" && i + 1 < args.size()) {
            const std::string& v = args[++i];
            if (v == "sha256") algo = Algo::Sha256;
            else if (v == "fnv") algo = Algo::Fnv;
            else { std::cerr << "[!] --algo soporta: fnv | sha256\n"; return 2; }
        } else if ((a == "--string" || a == "--file") && i + 1 < args.size()) {
            input_flag  = a;
            input_value = args[++i];
        }
    }

    if (input_flag.empty()) {
        std::cerr << "Uso: hash [--algo fnv|sha256] --string <texto> | --file <ruta>\n";
        return 2;
    }

    if (input_flag == "--string") {
        return (algo == Algo::Fnv) ? hash_string_fnv(input_value)
                                   : hash_string_sha(input_value);
    }
    return (algo == Algo::Fnv) ? hash_file_fnv(input_value)
                               : hash_file_sha(input_value);
}

}  // namespace edusec::hash_module
