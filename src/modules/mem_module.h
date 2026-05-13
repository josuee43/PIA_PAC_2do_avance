// =============================================================================
// modules/mem_module.h — Inspección de mapas de memoria de un proceso (Linux).
// -----------------------------------------------------------------------------
// Lee /proc/<pid>/maps y /proc/<pid>/status para mostrar regiones (rwxp),
// detectar segmentos sospechosos (zonas RWX que no sean stack/heap/anon) y
// reportar tamaños de RSS/VmPeak. NO escribe a /proc/<pid>/mem.
// =============================================================================
#ifndef EDUSEC_MODULES_MEM_MODULE_H
#define EDUSEC_MODULES_MEM_MODULE_H

#include <string>
#include <vector>

namespace edusec::mem_module {

int run(const std::vector<std::string>& args);

}  // namespace edusec::mem_module

#endif  // EDUSEC_MODULES_MEM_MODULE_H
