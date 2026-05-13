// =============================================================================
// modules/sniffer_module.cpp — Sniffer pasivo con AF_PACKET (Linux).
// -----------------------------------------------------------------------------
// Estrategia: socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) entrega tramas L2
// completas. Parseamos Ethernet (14B) -> IPv4 (variable, IHL*4) -> TCP/UDP.
// Para ICMP y otros protocolos imprimimos al menos protocolo + IPs.
// =============================================================================
#include "modules/sniffer_module.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#if defined(__linux__)
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>
#define EDUSEC_HAS_AF_PACKET 1
#else
#define EDUSEC_HAS_AF_PACKET 0
#endif

namespace edusec::sniffer_module {

#if EDUSEC_HAS_AF_PACKET

namespace {

std::string ip_to_str(std::uint32_t addr_net_order) {
    char buf[INET_ADDRSTRLEN];
    ::inet_ntop(AF_INET, &addr_net_order, buf, sizeof(buf));
    return buf;
}

std::string proto_name(std::uint8_t p) {
    switch (p) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: {
            std::ostringstream o;
            o << "IPproto=" << int(p);
            return o.str();
        }
    }
}

void print_packet(const std::uint8_t* data, std::size_t len, int idx) {
    if (len < sizeof(ethhdr) + sizeof(iphdr)) return;
    const auto* eth = reinterpret_cast<const ethhdr*>(data);
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        std::cout << "#" << idx << "  non-IPv4 (eth_proto=0x"
                  << std::hex << ntohs(eth->h_proto) << std::dec << ")\n";
        return;
    }

    const auto* ip = reinterpret_cast<const iphdr*>(data + sizeof(ethhdr));
    const std::size_t ip_hdr_len = ip->ihl * 4;
    const std::string src = ip_to_str(ip->saddr);
    const std::string dst = ip_to_str(ip->daddr);

    std::cout << "#" << idx << "  " << src << " -> " << dst
              << "  " << proto_name(ip->protocol);

    if (ip->protocol == IPPROTO_TCP && len >= sizeof(ethhdr) + ip_hdr_len + sizeof(tcphdr)) {
        const auto* tcp = reinterpret_cast<const tcphdr*>(
            data + sizeof(ethhdr) + ip_hdr_len);
        std::cout << "  sport=" << ntohs(tcp->source)
                  << "  dport=" << ntohs(tcp->dest);
        std::cout << "  flags=";
        if (tcp->syn) std::cout << "S";
        if (tcp->ack) std::cout << "A";
        if (tcp->fin) std::cout << "F";
        if (tcp->rst) std::cout << "R";
        if (tcp->psh) std::cout << "P";
    } else if (ip->protocol == IPPROTO_UDP &&
               len >= sizeof(ethhdr) + ip_hdr_len + sizeof(udphdr)) {
        const auto* udp = reinterpret_cast<const udphdr*>(
            data + sizeof(ethhdr) + ip_hdr_len);
        std::cout << "  sport=" << ntohs(udp->source)
                  << "  dport=" << ntohs(udp->dest);
    }

    std::cout << "  bytes=" << len << '\n';
}

}  // namespace

int run(const std::vector<std::string>& args) {
    int max_packets = 20;  // captura por defecto: 20 paquetes y termina

    for (std::size_t i = 0; i + 1 < args.size(); i += 2) {
        if (args[i] == "--count") {
            try { max_packets = std::stoi(args[i + 1]); } catch (...) {}
        }
    }

    int sock = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        std::cerr << "[!] socket(AF_PACKET) falló: " << std::strerror(errno) << '\n'
                  << "    Requiere CAP_NET_RAW. Ejecuta con sudo.\n";
        return 1;
    }

    std::cout << "[sniffer] Capturando hasta " << max_packets
              << " paquetes (Ctrl-C aborta)\n"
              << "------------------------------------------------------\n";

    std::uint8_t buf[2048];
    int captured = 0;
    while (captured < max_packets) {
        const ssize_t n = ::recv(sock, buf, sizeof(buf), 0);
        if (n < 0) {
            std::cerr << "[!] recv: " << std::strerror(errno) << '\n';
            break;
        }
        ++captured;
        print_packet(buf, static_cast<std::size_t>(n), captured);
    }

    ::close(sock);
    std::cout << "------------------------------------------------------\n"
              << "[sniffer] " << captured << " paquetes procesados\n";
    return 0;
}

#else  // !EDUSEC_HAS_AF_PACKET

int run(const std::vector<std::string>& /*args*/) {
    std::cerr << "[!] sniffer solo soportado en Linux (AF_PACKET).\n";
    return 1;
}

#endif

}  // namespace edusec::sniffer_module
