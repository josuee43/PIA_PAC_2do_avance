// =============================================================================
// modules/bruteforce_module.h — Ataque por diccionario contra FNV/SHA-256.
// -----------------------------------------------------------------------------
// Lee un archivo de diccionario (una palabra por línea) y compara el hash de
// cada candidato con el hash objetivo. Educacional: demuestra por qué los
// hashes débiles (FNV) o sin sal son recuperables y permite reflexionar sobre
// el coste computacional contra SHA-256.
// =============================================================================
#ifndef EDUSEC_MODULES_BRUTEFORCE_MODULE_H
#define EDUSEC_MODULES_BRUTEFORCE_MODULE_H

#include <string>
#include <vector>

namespace edusec::bruteforce_module {

int run(const std::vector<std::string>& args);

}  // namespace edusec::bruteforce_module

#endif  // EDUSEC_MODULES_BRUTEFORCE_MODULE_H
