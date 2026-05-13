// =============================================================================
// EduSec Toolkit — punto de entrada (Segundo Avance — Fase II/III)
// PIA PAC (Ene-Jun 2026) — Componente educativo de ciberseguridad en C++
// -----------------------------------------------------------------------------
// Despacha subcomandos: hash | procs | scan | brute | sniff | mem.
// Uso exclusivo en VM aisladas; ver README.md y docs/design.md.
// =============================================================================

#include <iostream>
#include <string>
#include <vector>

#include "modules/hash_module.h"
#include "modules/proc_module.h"
#include "modules/netscan_module.h"
#include "modules/bruteforce_module.h"
#include "modules/sniffer_module.h"
#include "modules/mem_module.h"

namespace {

constexpr const char* kVersion = "0.2.0-avance2";

void print_banner() {
    std::cout
        << "===============================================\n"
        << "  EduSec Toolkit v" << kVersion << "\n"
        << "  PIA PAC Ene-Jun 2026 - GRUPO 01\n"
        << "  Uso educativo exclusivo en VMs aisladas\n"
        << "===============================================\n";
}

void print_usage(const char* prog) {
    std::cout
        << "Uso: " << prog << " <subcomando> [opciones]\n\n"
        << "Subcomandos:\n"
        << "  hash    Hashing FNV-1a/32 o SHA-256 de cadena o archivo\n"
        << "          [--algo fnv|sha256]  --string <txt> | --file <ruta>\n\n"
        << "  procs   Enumera procesos vía /proc (Linux)\n\n"
        << "  scan    TCP connect-scan con banner-grab opcional\n"
        << "          --host <ip|host>  --ports <p1,p2,..>  [--banner]\n\n"
        << "  brute   Ataque por diccionario contra hash FNV/SHA-256\n"
        << "          --algo fnv|sha256 --hash <hex> --wordlist <ruta> [--limit N]\n\n"
        << "  sniff   Captura pasiva de paquetes (Linux AF_PACKET, root)\n"
        << "          [--count <N>]      Detiene tras N paquetes (default 20)\n\n"
        << "  mem     Inspecciona /proc/<pid>/maps de un proceso\n"
        << "          --pid <PID>\n\n"
        << "  --help, -h    Muestra esta ayuda\n"
        << "  --version     Imprime versión\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_banner();
        print_usage(argv[0]);
        return 0;
    }

    const std::string sub = argv[1];
    if (sub == "--help" || sub == "-h") { print_banner(); print_usage(argv[0]); return 0; }
    if (sub == "--version")             { std::cout << kVersion << '\n'; return 0; }

    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) args.emplace_back(argv[i]);

    if (sub == "hash")  return edusec::hash_module::run(args);
    if (sub == "procs") return edusec::proc_module::run(args);
    if (sub == "scan")  return edusec::netscan_module::run(args);
    if (sub == "brute") return edusec::bruteforce_module::run(args);
    if (sub == "sniff") return edusec::sniffer_module::run(args);
    if (sub == "mem")   return edusec::mem_module::run(args);

    std::cerr << "[!] Subcomando desconocido: " << sub << "\n\n";
    print_usage(argv[0]);
    return 2;
}
