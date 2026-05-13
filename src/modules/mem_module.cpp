// =============================================================================
// modules/mem_module.cpp — Lector de /proc/<pid>/maps + /proc/<pid>/status.
// -----------------------------------------------------------------------------
// El formato de /proc/<pid>/maps es:
//   addr_start-addr_end perms offset dev inode pathname
//   p.ej. 5651...000-5651...000 r-xp 00000000 fd:00 1234 /usr/bin/bash
// Marcamos como "[RWX]" cualquier región con permisos r+w+x (típico vector
// de ejecución de shellcode si no es esperado).
// =============================================================================
#include "modules/mem_module.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace edusec::mem_module {

namespace {

std::string read_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) return {};
    std::ostringstream oss;
    oss << in.rdbuf();
    return oss.str();
}

}  // namespace

int run(const std::vector<std::string>& args) {
    std::string pid;
    for (std::size_t i = 0; i + 1 < args.size(); i += 2) {
        if (args[i] == "--pid") pid = args[i + 1];
    }
    if (pid.empty()) {
        std::cerr << "Uso: mem --pid <PID>\n";
        return 2;
    }

    // --- status: extrae Name, VmRSS, VmPeak ---
    const std::string status = read_file("/proc/" + pid + "/status");
    if (status.empty()) {
        std::cerr << "[!] PID inválido o sin permiso: " << pid << '\n';
        return 1;
    }

    auto extract = [&](const std::string& key) -> std::string {
        const auto pos = status.find(key);
        if (pos == std::string::npos) return {};
        const auto eol = status.find('\n', pos);
        return status.substr(pos, eol - pos);
    };

    std::cout << "[mem] inspección de PID " << pid << "\n"
              << "  " << extract("Name:")   << "\n"
              << "  " << extract("Uid:")    << "\n"
              << "  " << extract("VmPeak:") << "\n"
              << "  " << extract("VmRSS:")  << "\n"
              << "------------------------------------------------------------\n"
              << " START-END                  PERMS  TAG    PATH\n"
              << "------------------------------------------------------------\n";

    // --- maps ---
    std::ifstream maps("/proc/" + pid + "/maps");
    if (!maps) {
        std::cerr << "[!] No se pudo leer /proc/" << pid << "/maps\n";
        return 1;
    }

    std::string line;
    int total = 0, rwx_count = 0;
    while (std::getline(maps, line)) {
        ++total;
        // Layout: 0000-0000 perms offset dev inode pathname
        std::istringstream ls(line);
        std::string range, perms, off, dev, inode, path;
        ls >> range >> perms >> off >> dev >> inode;
        std::getline(ls, path);

        std::string tag = " --- ";
        if (perms.size() >= 3 && perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
            tag = "[RWX]";
            ++rwx_count;
        } else if (perms.find('x') != std::string::npos) {
            tag = "[ X ]";
        }

        std::cout << " " << std::left << std::setw(26) << range
                  << " " << std::setw(5)  << perms
                  << " " << tag
                  << " " << path << '\n';
    }

    std::cout << "------------------------------------------------------------\n"
              << "Total regiones: " << total
              << "   Regiones RWX: " << rwx_count;
    if (rwx_count > 0) {
        std::cout << "  ¡posible shellcode o JIT! revisar.";
    }
    std::cout << '\n';
    return 0;
}

}  // namespace edusec::mem_module
