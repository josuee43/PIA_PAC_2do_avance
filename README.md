# EduSec Toolkit — PIA PAC — GRUPO 01

> Componente educativo de ciberseguridad en C++17. Uso exclusivo en VMs
> aisladas. Estado: **Segundo avance — Fase IV (Desarrollo Ofensivo
> Responsable)** · Versión `0.2.0-avance2`.

---

## 1. Objetivo del proyecto

Diseñar e implementar en C++ un **toolkit educativo modular** que demuestre,
de forma benigna y reproducible, varias técnicas fundamentales de
ciberseguridad: hashing, fuerza bruta por diccionario, enumeración local,
reconocimiento TCP con banner-grabbing, sniffing pasivo e inspección de
memoria. El binario resultante sirve además como objetivo para análisis
estático y dinámico (Ghidra / Radare2 / `strace` / x64dbg).

## 2. Descripción técnica del componente

Aplicación CLI única (`bin/main`) con seis subcomandos:

| Módulo       | Subcomando | Técnica demostrada                                      | Estado |
|--------------|------------|---------------------------------------------------------|--------|
| `hash`       | `hash`     | FNV-1a/32 + **SHA-256 puro (FIPS 180-4)**               | ✓      |
| `bruteforce` | `brute`    | **Ataque por diccionario** contra FNV/SHA-256           | ✓      |
| `procenum`   | `procs`    | Enumeración de procesos vía `/proc`                     | ✓      |
| `netscan`    | `scan`     | TCP connect-scan + **banner-grabbing** opcional         | ✓      |
| `sniffer`    | `sniff`    | **Captura pasiva** con raw sockets (`AF_PACKET`)        | ✓      |
| `mem`        | `mem`      | Inspección de `/proc/<pid>/maps` (detección de RWX)     | ✓      |

Validación funcional: SHA-256(`"abc"`) = `ba7816bf...015ad`, coincidente con
el vector de FIPS 180-4 §B.1. Detalles en `docs/tests.md`.

## 3. Alcance y límites

**Sí implementa:**

- Hashing SHA-256 portable y reproducible.
- Diccionario de palabras contra hashes propios u objetivos provistos.
- Reconocimiento TCP con timeout y banner-grab.
- Captura pasiva de paquetes en VMs aisladas.
- Lectura de mapas de memoria (`/proc/<pid>/maps`).
- Compilación de dos variantes (con símbolos y stripped) para análisis.

**No implementa (fuera de alcance, por diseño ético):**

- Persistencia, instalación como servicio o auto-arranque.
- Exfiltración de datos a destinos externos.
- Lectura/escritura de `/proc/<pid>/mem`.
- Explotación de vulnerabilidades reales contra terceros.
- Capacidades destructivas (ransomware, wipe, etc.).
- Ejecución fuera de las VMs aisladas del equipo.

## 4. Cómo compilar

Requisitos: `g++` con C++17 (`>= 7.0`) y `make`. Sin dependencias externas.

```bash
make            # construye bin/main-debug y bin/main (stripped)
make debug      # solo binario con símbolos
make release    # solo binario stripped
make analysis   # genera artefactos en analysis/
make clean      # elimina build/ y bin/
```

Salida:

```
bin/main-debug   ELF64 PIE, ~576 KB, con símbolos (-g -O0)
bin/main         ELF64 PIE, ~68 KB, stripped (-O2 -strip-all)
```

## 5. Cómo ejecutar

```bash
./main --help
./main --version

# Hashing
./main hash --string "hola"
./main hash --algo sha256 --string "abc"
./main hash --algo sha256 --file /etc/hostname

# Enumeración de procesos
./main procs

# TCP scan + banner
./main scan --host 127.0.0.1 --ports 22,80,443 --banner

# Fuerza bruta por diccionario
./main brute --algo sha256 \
    --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
    --wordlist /usr/share/wordlists/rockyou.txt --limit 100000

# Sniffer pasivo (requiere root: CAP_NET_RAW)
sudo ./main sniff --count 20

# Inspección de memoria
./main mem --pid 1
```

## 6. Integrantes y responsabilidades técnicas

| Integrante               | Matrícula | Responsabilidad principal                          |
|--------------------------|-----------|----------------------------------------------------|
| Josue Arcos              |  2009127  | Coordinación técnica, `main.cpp`, dispatcher, `mem` |
| Johan Garay              |  2001776  | `hash` (FNV + SHA-256) y `bruteforce`              |
| Johan Garay              |  2001776  | `procenum`                                         |
| Andrea Abundiz           |  2051169  | `netscan` (TCP + banner), `sniffer`                |
| Andrea Abundiz           |  2051169  | Documentación, evidencias, análisis estático       |

## 7. Estructura de directorios

```
PIA/
├── README.md
├── makefile
├── .gitignore
├── src/
│   ├── main.cpp
│   └── modules/
│       ├── sha256.{h,cpp}
│       ├── hash_module.{h,cpp}
│       ├── bruteforce_module.{h,cpp}
│       ├── proc_module.{h,cpp}
│       ├── netscan_module.{h,cpp}
│       ├── sniffer_module.{h,cpp}
│       └── mem_module.{h,cpp}
├── main                      (copia stripped en raíz — ejecución cómoda)
├── bin/
│   ├── main-debug            (con símbolos, para análisis)
│   └── main                  (stripped, para entrega — rúbrica)
├── docs/
│   ├── design.md
│   ├── tests.md              (comandos + outputs reales)
│   └── report_draft.md       (borrador técnico 2-3 págs.)
├── analysis/
│   ├── notes.md              (notas RE manuales)
│   ├── strings_debug.txt
│   ├── strings_stripped.txt
│   ├── symbols.txt
│   ├── elf_header.txt
│   └── sections.txt
└── evidence/
    ├── compilacion.png       (1er avance, conservada)
    ├── ejecucion.png         (1er avance, conservada)
    ├── exec_avance2_*.png    (2 capturas de ejecución actuales)
    ├── ghidra_or_radare.png  (1 captura de análisis estático)
    └── sniff_traffic.png     (1 captura de tráfico)
```

## 8. Tags Git

```bash
# 1er avance — ya entregado
git tag -a pia-avance-1 -m "PIA: primer avance — EduSec Toolkit"

# 2do avance — actual
git add -A
git commit -m "PIA: segundo avance — Grupo 01"
git tag -a pia-avance-2 -m "PIA: segundo avance — Grupo 01"
```

---

## 9. Evidencias del Segundo Avance

Pendientes de añadir a `/evidence/` (cada equipo en su VM):

1. `exec_avance2_hash_brute.png` — secuencia `hash --algo sha256 ...` →
   `brute ...` mostrando el `[+] MATCH`.
2. `exec_avance2_scan_banner.png` — `scan ... --banner` contra un servicio
   levantado en la VM (p. ej. `python3 -m http.server 8080`).
3. `ghidra_main_dispatch.png` — Ghidra mostrando el switch del `main` y la
   función `edusec::sha256::Context::process_block` identificada por sus
   constantes K[64].
4. `sniff_traffic.png` — terminal con `sudo ./main sniff --count 20`
   capturando tráfico paralelo (ping + curl en otra terminal).

> Las capturas del primer avance (`compilacion.png`, `ejecucion.png`) se
> conservan en `/evidence/` como antecedente.
