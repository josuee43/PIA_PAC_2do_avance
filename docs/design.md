# Diseño técnico — EduSec Toolkit (PIA PAC — Segundo Avance)

## 1. Arquitectura general

Aplicación CLI monolítica en C++17. `src/main.cpp` actúa como *dispatcher*:
toma `argv[1]` como subcomando, empaqueta el resto de argumentos y delega a
una función `run(args)` de cada módulo. Todos los módulos comparten esa firma
para uniformar la interfaz y simplificar el grafo de llamadas al hacer
reversing.

```
+------------------+         argv[1] = subcomando
|   main.cpp       | ---------------------------+
|  (dispatcher)    |                            |
+------------------+                            v
                ┌──────┬──────┬──────┬──────┬──────┬──────┐
                │ hash │brute │procs │ scan │sniff │ mem  │
                └──────┴──────┴──────┴──────┴──────┴──────┘
                  │       │      │      │      │      │
                  v       v      v      v      v      v
              sha256  hash_mod /proc  POSIX  AF_   /proc
                       (FNV)         sockets PACKET maps
```

## 2. Módulos y su función

| Módulo              | Responsabilidad                                                | Avance |
|---------------------|----------------------------------------------------------------|:------:|
| `sha256`            | Implementación pura de SHA-256 (FIPS 180-4).                   |   2    |
| `hash_module`       | Hashing FNV-1a/32 y SHA-256 sobre cadena/archivo.              |   2    |
| `bruteforce_module` | Diccionario contra hash objetivo (FNV o SHA-256).              |   2    |
| `proc_module`       | Enumeración de procesos via `/proc`.                           |   1    |
| `netscan_module`    | TCP connect-scan no bloqueante con timeout y banner-grab.      |   2    |
| `sniffer_module`    | Captura pasiva con `AF_PACKET` y parseo Eth/IPv4/TCP/UDP.      |   2    |
| `mem_module`        | Lector de `/proc/<pid>/maps` con etiqueta `[RWX]`.             |   2    |

## 3. Flujo general del programa

1. `main` valida `argc` / muestra `--help` o `--version`.
2. Empaqueta `argv[2..]` en `std::vector<std::string>` y despacha al módulo
   según `argv[1]`.
3. Cada módulo parsea sus flags por su cuenta (lo cual mantiene los módulos
   independientes y facilita probar cada uno en aislado).
4. El módulo devuelve `int rc`; `main` lo propaga como código de salida.

## 4. Decisiones técnicas relevantes

- **Sin OpenSSL ni libpcap.** Toda la criptografía y la captura de paquetes
  se implementan sobre cabeceras POSIX/Linux estándar. Esto reduce la
  superficie del binario y elimina simbología de terceros que opacaría el
  análisis estático.
- **SHA-256 como `class Context` incremental.** Permite hashear flujos
  grandes (archivos) sin cargar todo en memoria. `update()` + `finalize()`.
- **TCP scan no bloqueante con `select()`.** Más eficiente y más fácil de
  observar el comportamiento de timeout en análisis dinámico.
- **Sniffer con `recv()` síncrono y contador `--count`.** Evita
  hilos/threads, simplifica el control de la sesión y reduce el grafo de
  llamadas a una secuencia lineal.
- **Compilación dual.** `bin/main-debug` con `-O0 -g` para Ghidra/gdb;
  `bin/main` con `-O2` y `strip --strip-all` para entrega y ejercicios de
  reversing "ciego".

## 5. Dependencias técnicas

- `libstdc++` (C++17 STL).
- Cabeceras POSIX: `<unistd.h>`, `<fcntl.h>`, `<sys/socket.h>`,
  `<sys/select.h>`, `<netdb.h>`, `<arpa/inet.h>`, `<dirent.h>`.
- Cabeceras específicas de Linux: `<linux/if_ether.h>`,
  `<netinet/{ip,tcp,udp}.h>`. (El módulo `sniffer` requiere kernel Linux y
  CAP_NET_RAW.)
- Herramientas de análisis (no requeridas en compilación, sí en uso):
  `strings`, `nm`, `readelf`, `objdump`, Ghidra, Radare2, Wireshark.

## 6. Plan a Fase V

- Endurecimiento del binario final con `-fstack-protector-strong`,
  `-D_FORTIFY_SOURCE=2`, `-fcf-protection=full`, `-Wl,-z,now -Wl,-z,relro`.
- Filtros BPF para `sniffer` (`setsockopt(SO_ATTACH_FILTER)`).
- Banner-grabbing activo con probes específicos por puerto.
- Reporte final con análisis dinámico completo (`strace -f`, `ltrace`,
  Ghidra) y métricas comparativas FNV vs SHA-256 (H/s, coste teórico).
