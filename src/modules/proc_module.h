// =============================================================================
// modules/proc_module.h — Enumeración de procesos vía /proc (Linux)
// -----------------------------------------------------------------------------
// Recorre /proc, identifica los directorios cuyo nombre es un PID y lee
// /proc/<pid>/comm para obtener el nombre del binario en ejecución.
// En Fase II se ampliará para extraer cmdline, UID, mapas de memoria y para
// detectar inyección/ocultamiento básico (técnicas defensivas).
// =============================================================================
#ifndef EDUSEC_MODULES_PROC_MODULE_H
#define EDUSEC_MODULES_PROC_MODULE_H

#include <string>
#include <vector>

namespace edusec::proc_module {

// Punto de entrada del subcomando `procs`.
int run(const std::vector<std::string>& args);

}  // namespace edusec::proc_module

#endif  // EDUSEC_MODULES_PROC_MODULE_H
