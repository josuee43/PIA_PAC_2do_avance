// =============================================================================
// modules/sha256.cpp — SHA-256 puro (FIPS 180-4)
// -----------------------------------------------------------------------------
// Las constantes K[64] son los primeros 32 bits de la parte fraccional de las
// raíces cúbicas de los primeros 64 primos. H0[8] son los primeros 32 bits de
// la parte fraccional de las raíces cuadradas de los primeros 8 primos.
// Estas constantes son una firma reconocible en análisis estático.
// =============================================================================
#include "modules/sha256.h"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace edusec::sha256 {

namespace {

constexpr std::uint32_t kK[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

constexpr std::uint32_t kH0[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

inline std::uint32_t rotr(std::uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

}  // namespace

Context::Context() : h_(), buffer_(), buffer_len_(0), bit_count_(0) {
    for (int i = 0; i < 8; ++i) h_[i] = kH0[i];
}

void Context::process_block(const std::uint8_t block[64]) {
    std::uint32_t w[64];
    for (int t = 0; t < 16; ++t) {
        w[t] = (std::uint32_t(block[t * 4 + 0]) << 24) |
               (std::uint32_t(block[t * 4 + 1]) << 16) |
               (std::uint32_t(block[t * 4 + 2]) << 8)  |
                std::uint32_t(block[t * 4 + 3]);
    }
    for (int t = 16; t < 64; ++t) {
        const std::uint32_t s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
        const std::uint32_t s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }

    std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    std::uint32_t e = h_[4], f = h_[5], g = h_[6], hh = h_[7];

    for (int t = 0; t < 64; ++t) {
        const std::uint32_t S1  = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t ch  = (e & f) ^ (~e & g);
        const std::uint32_t T1  = hh + S1 + ch + kK[t] + w[t];
        const std::uint32_t S0  = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t T2  = S0 + maj;
        hh = g;  g = f;  f = e;  e = d + T1;
        d  = c;  c = b;  b = a;  a = T1 + T2;
    }

    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
    h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += hh;
}

void Context::update(const void* data, std::size_t len) {
    const auto* p = static_cast<const std::uint8_t*>(data);
    bit_count_ += std::uint64_t(len) * 8;

    while (len > 0) {
        const std::size_t take = std::min(len, std::size_t(64) - buffer_len_);
        std::memcpy(&buffer_[buffer_len_], p, take);
        buffer_len_ += take;
        p          += take;
        len        -= take;
        if (buffer_len_ == 64) {
            process_block(buffer_.data());
            buffer_len_ = 0;
        }
    }
}

std::array<std::uint8_t, 32> Context::finalize() {
    // Padding: append 0x80, after-pad zeros, last 8 bytes = bit_count big-endian.
    buffer_[buffer_len_++] = 0x80;
    if (buffer_len_ > 56) {
        while (buffer_len_ < 64) buffer_[buffer_len_++] = 0;
        process_block(buffer_.data());
        buffer_len_ = 0;
    }
    while (buffer_len_ < 56) buffer_[buffer_len_++] = 0;

    for (int i = 7; i >= 0; --i) {
        buffer_[buffer_len_++] = static_cast<std::uint8_t>(bit_count_ >> (i * 8));
    }
    process_block(buffer_.data());

    std::array<std::uint8_t, 32> out{};
    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = static_cast<std::uint8_t>(h_[i] >> 24);
        out[i * 4 + 1] = static_cast<std::uint8_t>(h_[i] >> 16);
        out[i * 4 + 2] = static_cast<std::uint8_t>(h_[i] >> 8);
        out[i * 4 + 3] = static_cast<std::uint8_t>(h_[i]);
    }
    return out;
}

std::string Context::to_hex(const std::array<std::uint8_t, 32>& digest) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : digest) oss << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

std::string hash_string(const std::string& s) {
    Context ctx;
    ctx.update(s.data(), s.size());
    return Context::to_hex(ctx.finalize());
}

std::string hash_bytes(const void* data, std::size_t len) {
    Context ctx;
    ctx.update(data, len);
    return Context::to_hex(ctx.finalize());
}

}  // namespace edusec::sha256
