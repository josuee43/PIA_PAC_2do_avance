// =============================================================================
// modules/sniffer_module.h — Captura pasiva de paquetes (Linux, AF_PACKET).
// -----------------------------------------------------------------------------
// Requiere capability CAP_NET_RAW (root). Captura, parsea cabeceras Ethernet /
// IPv4 / TCP|UDP y muestra un resumen por línea. NO escribe a disco — solo
// stdout, manteniendo el perfil benigno y no persistente del toolkit.
// =============================================================================
#ifndef EDUSEC_MODULES_SNIFFER_MODULE_H
#define EDUSEC_MODULES_SNIFFER_MODULE_H

#include <string>
#include <vector>

namespace edusec::sniffer_module {

int run(const std::vector<std::string>& args);

}  // namespace edusec::sniffer_module

#endif  // EDUSEC_MODULES_SNIFFER_MODULE_H
