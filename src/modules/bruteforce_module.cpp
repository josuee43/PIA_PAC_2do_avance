// =============================================================================
// modules/bruteforce_module.cpp — Ataque por diccionario contra hash conocido.
// -----------------------------------------------------------------------------
// Uso: brute --algo fnv|sha256 --hash <hex> --wordlist <ruta> [--limit N]
// Estrategia: streaming del diccionario, una palabra por iteración, sin
// cargar el archivo completo a memoria. Comparación case-insensitive del hex.
// =============================================================================
#include "modules/bruteforce_module.h"
#include "modules/hash_module.h"
#include "modules/sha256.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <string>

namespace edusec::bruteforce_module {

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

}  // namespace

int run(const std::vector<std::string>& args) {
    std::string algo = "fnv";
    std::string target_hash;
    std::string wordlist;
    std::size_t limit = 0;  // 0 = sin límite

    for (std::size_t i = 0; i + 1 < args.size(); i += 2) {
        const auto& flag = args[i];
        const auto& val  = args[i + 1];
        if      (flag == "--algo")     algo = val;
        else if (flag == "--hash")     target_hash = to_lower(val);
        else if (flag == "--wordlist") wordlist = val;
        else if (flag == "--limit")    limit = std::stoul(val);
    }

    if (target_hash.empty() || wordlist.empty() ||
        (algo != "fnv" && algo != "sha256")) {
        std::cerr << "Uso: brute --algo fnv|sha256 --hash <hex> "
                  << "--wordlist <ruta> [--limit N]\n";
        return 2;
    }

    // Normaliza prefijos "0x"
    if (target_hash.rfind("0x", 0) == 0) target_hash.erase(0, 2);

    std::ifstream in(wordlist);
    if (!in) {
        std::cerr << "[!] No se pudo abrir diccionario: " << wordlist << '\n';
        return 1;
    }

    std::cout << "[brute] algo=" << algo
              << "  hash=" << target_hash
              << "  wordlist=" << wordlist;
    if (limit) std::cout << "  limit=" << limit;
    std::cout << '\n' << "--------------------------------\n";

    const auto t_start = std::chrono::steady_clock::now();
    std::size_t tried = 0;
    std::string line;
    bool found = false;

    while (std::getline(in, line)) {
        // Trim básico: quita \r si viene de Windows.
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        std::string candidate_hash =
            (algo == "fnv") ? edusec::hash_module::fnv1a_32_hex(line)
                            : edusec::sha256::hash_string(line);

        ++tried;
        if (candidate_hash == target_hash) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t_start).count();
            std::cout << "[+] MATCH encontrado en " << tried
                      << " intentos (" << elapsed << " ms)\n"
                      << "    password = \"" << line << "\"\n";
            found = true;
            break;
        }

        if (limit && tried >= limit) break;
    }

    if (!found) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t_start).count();
        std::cout << "[-] Sin match. Probadas " << tried
                  << " palabras en " << elapsed << " ms\n";
        return 1;
    }
    return 0;
}

}  // namespace edusec::bruteforce_module
