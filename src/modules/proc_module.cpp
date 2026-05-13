// =============================================================================
// modules/proc_module.cpp — Implementación de enumeración de procesos.
// Funciona en Linux (lee /proc). En otros SO devuelve aviso y código != 0.
// =============================================================================
#include "modules/proc_module.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

#if defined(__linux__)
#include <dirent.h>
#endif

namespace edusec::proc_module {

namespace {

bool is_all_digits(const std::string& s) {
    if (s.empty()) return false;
    return std::all_of(s.begin(), s.end(),
                       [](unsigned char c) { return std::isdigit(c) != 0; });
}

std::string read_first_line(const std::string& path) {
    std::ifstream in(path);
    if (!in) return {};
    std::string line;
    std::getline(in, line);
    return line;
}

}  // namespace

int run(const std::vector<std::string>& args) {
    (void)args;  // sin opciones en este avance

#if defined(__linux__)
    DIR* dir = opendir("/proc");
    if (dir == nullptr) {
        std::cerr << "[!] /proc no accesible.\n";
        return 1;
    }

    std::cout << std::left << std::setw(8) << "PID"
              << "COMM\n"
              << std::string(40, '-') << '\n';

    int count = 0;
    while (auto* entry = readdir(dir)) {
        const std::string name = entry->d_name;
        if (!is_all_digits(name)) continue;

        const std::string comm = read_first_line("/proc/" + name + "/comm");
        std::cout << std::left << std::setw(8) << name << comm << '\n';
        ++count;
    }
    closedir(dir);

    std::cout << std::string(40, '-') << '\n'
              << "Total: " << count << " procesos\n";
    return 0;
#else
    std::cerr << "[!] El módulo procs solo está soportado en Linux en este avance.\n";
    return 1;
#endif
}

}  // namespace edusec::proc_module
