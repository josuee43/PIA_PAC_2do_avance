// =============================================================================
// modules/netscan_module.h — TCP connect-scan simple con sockets POSIX.
// -----------------------------------------------------------------------------
// Para cada puerto solicitado abre un socket TCP, intenta connect() con
// timeout no bloqueante y reporta el estado del puerto (ABIERTO / CERRADO).
// En Fase II se añadirá banner-grabbing, paralelismo y soporte UDP.
// =============================================================================
#ifndef EDUSEC_MODULES_NETSCAN_MODULE_H
#define EDUSEC_MODULES_NETSCAN_MODULE_H

#include <string>
#include <vector>

namespace edusec::netscan_module {

// Punto de entrada del subcomando `scan`.
int run(const std::vector<std::string>& args);

}  // namespace edusec::netscan_module

#endif  // EDUSEC_MODULES_NETSCAN_MODULE_H
