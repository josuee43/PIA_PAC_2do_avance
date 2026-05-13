// =============================================================================
// modules/netscan_module.cpp — TCP connect-scan con banner-grab opcional.
// -----------------------------------------------------------------------------
// Estrategia: socket() -> non-blocking -> connect() -> select() con timeout.
// Si select() reporta el socket escribible y SO_ERROR == 0  => puerto ABIERTO.
// Con --banner se intenta recv() corto tras la conexión: muchos servicios
// (SSH, FTP, SMTP) emiten un banner sin recibir input — útil para
// reconocimiento básico al estilo `nc -v target port`.
// =============================================================================
#include "modules/netscan_module.h"

#include <cerrno>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define EDUSEC_HAS_SOCKETS 1
#else
#define EDUSEC_HAS_SOCKETS 0
#endif

namespace edusec::netscan_module {

namespace {

constexpr int kTimeoutSeconds = 1;     // timeout connect()
constexpr int kBannerTimeoutMs = 800;  // timeout para banner-grab

std::vector<int> parse_ports(const std::string& csv) {
    std::vector<int> ports;
    std::stringstream ss(csv);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (item.empty()) continue;
        try {
            const int p = std::stoi(item);
            if (p > 0 && p <= 65535) ports.push_back(p);
        } catch (...) {}
    }
    return ports;
}

#if EDUSEC_HAS_SOCKETS

bool resolve_host(const std::string& host, in_addr& out) {
    if (inet_pton(AF_INET, host.c_str(), &out) == 1) return true;
    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) return false;
    out = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return true;
}

// Sanea el banner para impresión segura: quita CR/LF y caracteres no imprimibles.
std::string sanitize(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '\r' || c == '\n') break;
        if (c >= 0x20 && c < 0x7F) out.push_back(static_cast<char>(c));
    }
    if (out.size() > 80) out = out.substr(0, 77) + "...";
    return out;
}

// Devuelve {abierto, banner}.
std::pair<bool, std::string> probe_port(const in_addr& addr, int port, bool grab) {
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return {false, {}};

    const int flags = ::fcntl(sock, F_GETFL, 0);
    ::fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port   = htons(static_cast<uint16_t>(port));
    target.sin_addr   = addr;

    bool open = false;
    const int rc = ::connect(sock, reinterpret_cast<sockaddr*>(&target), sizeof(target));

    if (rc == 0) {
        open = true;
    } else if (errno == EINPROGRESS) {
        fd_set wset; FD_ZERO(&wset); FD_SET(sock, &wset);
        timeval tv{kTimeoutSeconds, 0};
        if (::select(sock + 1, nullptr, &wset, nullptr, &tv) > 0) {
            int so_err = 0; socklen_t len = sizeof(so_err);
            ::getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &len);
            open = (so_err == 0);
        }
    }

    std::string banner;
    if (open && grab) {
        // Vuelve a bloqueante con timeout corto.
        ::fcntl(sock, F_SETFL, flags);
        timeval rto{0, kBannerTimeoutMs * 1000};
        ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto));

        char buf[256] = {0};
        const ssize_t n = ::recv(sock, buf, sizeof(buf) - 1, 0);
        if (n > 0) banner = sanitize(std::string(buf, static_cast<std::size_t>(n)));
    }

    ::close(sock);
    return {open, banner};
}

#endif  // EDUSEC_HAS_SOCKETS

}  // namespace

int run(const std::vector<std::string>& args) {
    std::string host;
    std::vector<int> ports;
    bool grab = false;

    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& flag = args[i];
        if (flag == "--banner") { grab = true; continue; }
        if (i + 1 >= args.size()) continue;
        const auto& value = args[i + 1];
        if      (flag == "--host")  { host  = value; ++i; }
        else if (flag == "--ports") { ports = parse_ports(value); ++i; }
    }

    if (host.empty() || ports.empty()) {
        std::cerr << "Uso: scan --host <ip|host> --ports <p1,...> [--banner]\n";
        return 2;
    }

#if !EDUSEC_HAS_SOCKETS
    std::cerr << "[!] netscan no soportado en esta plataforma.\n";
    return 1;
#else
    in_addr addr{};
    if (!resolve_host(host, addr)) {
        std::cerr << "[!] No se pudo resolver el host: " << host << '\n';
        return 1;
    }

    char ip_str[INET_ADDRSTRLEN];
    ::inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    std::cout << "[scan] objetivo: " << host << " (" << ip_str << ")"
              << (grab ? "  [+banner]" : "") << "\n"
              << "----------------------------------------------------------\n"
              << " PUERTO   ESTADO    BANNER\n"
              << "----------------------------------------------------------\n";

    int open_count = 0;
    for (int port : ports) {
        const auto [open, banner] = probe_port(addr, port, grab);
        if (open) ++open_count;
        std::cout << "  " << port
                  << std::string(port < 10 ? 6 : port < 100 ? 5 : port < 1000 ? 4 : port < 10000 ? 3 : 2, ' ')
                  << (open ? "ABIERTO  " : "CERRADO  ")
                  << banner << '\n';
    }

    std::cout << "----------------------------------------------------------\n"
              << "Resumen: " << open_count << " abiertos / " << ports.size() << " probados\n";
    return 0;
#endif
}

}  // namespace edusec::netscan_module
