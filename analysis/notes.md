# Notas de análisis preliminar — EduSec Toolkit

Análisis estático **inicial** del binario propio antes de aplicar las técnicas
formales con Ghidra / Radare2 (que se incluyen como evidencia en `/evidence`).
Toda la inspección se realizó con herramientas estándar de GNU binutils
(`strings`, `nm`, `readelf`, `objdump`) y con el propio toolkit (`./main
hash --algo sha256 --file ...`).

## 1. Identificación del binario

| Archivo               | Tipo                            | Tamaño   | SHA-256 |
|-----------------------|---------------------------------|---------:|---------|
| `bin/main-debug`    | ELF64 PIE, con símbolos (`-g`)  | 576 360 B | `6e2d6050dcab76fbf45c273e62162b198b9c72061d86ce431c22bcb473096b81` |
| `bin/main`          | ELF64 PIE, **stripped**         |  67 888 B | `17ef85bac18f8bdf0a661ac8a790289c3ddad22b073fbd8bca204b8e80f59d23` |

> Los hashes se generaron con el propio binario (`hash --algo sha256 --file`)
> como demostración auto-verificable: el toolkit puede hashear su propio binario.

Datos clave de `readelf -h`:

- Class: **ELF64**, little endian.
- Type: **DYN** (Position-Independent Executable) → ASLR habilitado.
- Machine: **x86-64**.
- Entry point: `0x48f0` (rutina `_start` de glibc).

## 2. Strings extraídos (relevantes)

### 2.1. Strings de control (visibles también tras `strip`)

`analysis/strings_stripped.txt` conserva los literales del programa porque
viven en `.rodata`, no en la tabla de símbolos. Algunos representativos:

```
--algo            --string         --wordlist      --banner
--file            --ports          --pid           --count
--hash            --host           --limit         --version
hash              procs            scan            brute
sniff             mem              EduSec Toolkit  0.2.0-avance2
GRUPO 01          Uso educativo exclusivo en VMs aisladas
```

**Interpretación reversing:** un analista que inspeccione el binario stripped
puede recuperar **toda la superficie de subcomandos y flags** solo con
`strings`. Esto es esperado en un toolkit CLI — no se hizo ofuscación porque
el componente es educativo. En un payload real estos strings se ocultarían
con XOR/cifrado simple, lo que será discutido en el reporte final.

### 2.2. Strings comprometedores que **no** deben aparecer

Auditamos para confirmar el alcance benigno declarado:

```bash
$ grep -iE 'http://|https://|wget|curl|nc -e|/bin/sh|exec\(' analysis/strings_stripped.txt
# (sin resultados)
```

→ El binario **no** contiene URLs, comandos de exfiltración ni shells
encadenadas. Coherente con el alcance del README (no exfiltración, no
persistencia).

## 3. Funciones identificadas

`nm --defined-only --demangle bin/main-debug` confirma la modularidad del
diseño. Funciones públicas relevantes (ordenadas por offset):

| Offset     | Símbolo                                  | Módulo        |
|------------|------------------------------------------|---------------|
| `0x51a4`   | `main`                                   | entry         |
| `0x68d5`   | `edusec::bruteforce_module::run`         | bruteforce    |
| `0x7921`   | `edusec::hash_module::fnv1a_32`          | hash (FNV)    |
| `0x797e`   | `edusec::hash_module::to_hex_u32`        | hash (FNV)    |
| `0x7a81`   | `edusec::hash_module::fnv1a_32_hex`      | hash (FNV)    |
| `0x8201`   | `edusec::hash_module::run`               | hash dispatch |
| `0x8a5b`   | `edusec::mem_module::run`                | mem           |
| `0xa544`   | `edusec::netscan_module::run`            | netscan       |
| `0xc1dd`   | `edusec::proc_module::run`               | procs         |
| `0xcaee`   | `edusec::sha256::Context::Context()`     | sha256 ctor   |
| `0xcbc8`   | `edusec::sha256::Context::process_block` | sha256 core   |
| `0xd194`   | `edusec::sha256::Context::update`        | sha256        |
| `0xd2ce`   | `edusec::sha256::Context::finalize`      | sha256        |
| `0xd55e`   | `edusec::sha256::Context::to_hex`        | sha256        |
| `0xd6cd`   | `edusec::sha256::hash_string`            | sha256 wrap   |
| `0xe202`   | `edusec::sniffer_module::run`            | sniffer       |

Cada `run(args)` es el punto de entrada uniforme del despachador. Esta
homogeneidad facilita el análisis: en Ghidra, una vez localizado uno se
deducen los demás por convención de llamada idéntica.

En la versión **stripped**, estos nombres desaparecen — pero las constantes
mágicas siguen permitiendo reconocer rutinas:

- **SHA-256** se identifica al ver el array de 64 constantes `K[t]`
  comenzando con `0x428a2f98, 0x71374491, ...` (cube-roots primos). Está en
  `.rodata`.
- **FNV-1a/32** se identifica por la pareja `0x811C9DC5` (offset) y
  `0x01000193` (prime). Está en `.text` como inmediato.

## 4. Mapa de secciones (PE/ELF)

De `analysis/sections.txt`:

```
.text          ~36 KB   código ejecutable
.rodata         ~3 KB   constantes (incluye SHA-256 K[64] y strings)
.data.rel.ro   ~970 B   vtables, jump tables del switch de subcomandos
.data           24 B    inicializaciones globales no-const
.bss          ~570 B    estado no inicializado
.init/.fini    ~40 B    constructores/destructores globales
```

Observaciones:

- `.text` no es `wx` → DEP/NX habilitado correctamente por el linker.
- No hay sección `.note.gnu.property` con CET → posible mejora futura
  (`-fcf-protection=full`).
- `PIE` + ASLR habilitados.

## 5. Hipótesis a verificar con Ghidra / Radare2

1. Confirmar el grafo de llamadas: `main → switch(argv[1]) → run` por módulo.
2. Identificar visualmente la ronda principal de SHA-256 (`for t=0..63`) en
   `process_block`. Detectarla por el patrón de cuatro lecturas a `K[t]` y
   el cálculo de `T1` y `T2`.
3. Verificar que el módulo `sniffer` realiza `socket(AF_PACKET, SOCK_RAW,
   htons(0x0003))` (ETH_P_ALL=0x0003).
4. Localizar el limit en `--banner` (256 bytes de buffer y timeout 800 ms en
   `recv`).
5. Buscar funciones no referenciadas → dead code que pueda eliminarse en la
   entrega final.

## 6. Comandos para reproducir el análisis

```bash
make analysis            # regenera todos los artefactos en analysis/
strings -a -n 6 bin/main | less
nm -D --demangle bin/main-debug
readelf -a bin/main | less
objdump -d -M intel bin/main-debug | less
checksec --file=bin/main     # (de pwntools, recomendado)
```

Para Ghidra: importar `bin/main-debug` (con símbolos) primero para validar
ground truth; luego importar `bin/main` (stripped) y verificar cuánto se
puede reconstruir solo a partir de constantes y patrones — esto es el
ejercicio central del reverse engineering en este proyecto.
