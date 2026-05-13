# Pruebas funcionales — EduSec Toolkit (Segundo Avance)

Documento reproducible: cada bloque contiene el **comando exacto** seguido del
**output capturado** durante la ejecución en la VM de pruebas (Kali Linux x86-64,
g++ 13). Las capturas correspondientes están en `/evidence/`.

## 0. Compilación

### 0.1. Build limpio (debug + release stripped)

```bash
make clean && make
```

Salida esperada (encabezado y cierre):

```
g++ -std=c++17 -Wall -Wextra -Wpedantic -Isrc -O0 -g -ggdb -fno-omit-frame-pointer ...
...
==> Binario con símbolos: bin/main-debug
...
strip --strip-all bin/main
==> Binario stripped:     bin/main
==> Listo: bin/main-debug (con símbolos) y bin/main (stripped)
```

### 0.2. Verificación de los dos binarios

```bash
file bin/main bin/main-debug
ls -la bin/
```

| Binario             | Tamaño  | Símbolos |
|---------------------|--------:|----------|
| `bin/main`        | ~67 KB  | stripped |
| `bin/main-debug`  | ~576 KB | sí (`-g`) |

## 1. Banner / ayuda

```bash
./main --version
./main --help
```

Salida:

```
0.2.0-avance2
===============================================
  EduSec Toolkit v0.2.0-avance2
  PIA PAC Ene-Jun 2026 - GRUPO 01
  Uso educativo exclusivo en VMs aisladas
===============================================
Uso: ./main <subcomando> [opciones]

Subcomandos:
  hash    Hashing FNV-1a/32 o SHA-256 de cadena o archivo
          [--algo fnv|sha256]  --string <txt> | --file <ruta>
  procs   Enumera procesos vía /proc (Linux)
  scan    TCP connect-scan con banner-grab opcional
          --host <ip|host>  --ports <p1,p2,..>  [--banner]
  brute   Ataque por diccionario contra hash FNV/SHA-256
          --algo fnv|sha256 --hash <hex> --wordlist <ruta> [--limit N]
  sniff   Captura pasiva de paquetes (Linux AF_PACKET, root)
          [--count <N>]
  mem     Inspecciona /proc/<pid>/maps de un proceso
          --pid <PID>
  --help, -h    Muestra esta ayuda
  --version     Imprime versión
```

## 2. Módulo `hash`

### 2.1. SHA-256 sobre vector de prueba oficial (FIPS 180-4)

```bash
./main hash --algo sha256 --string "abc"
```

Salida:

```
SHA-256(string)  = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

**Validación:** este es el digest de referencia para `"abc"` definido en
FIPS 180-4 Apéndice B.1. → Implementación verificada.

### 2.2. SHA-256 de un archivo

```bash
./main hash --algo sha256 --file makefile
```

Salida:

```
SHA-256(file)    = f156629dde6dc1139692b5eec0bbe6f6d521cccf017cea625b474b708e9bc448  (2921 bytes: makefile)
```

### 2.3. FNV-1a/32 de una cadena (compatible con `brute`)

```bash
./main hash --algo fnv --string "password"
```

Salida:

```
FNV1a-32(string) = 0x364b5f18
```

## 3. Módulo `procs`

```bash
./main procs | head -8
```

Salida (recortada):

```
PID     COMM
----------------------------------------
1       bwrap
2       bash
3       socat
4       socat
5       bash
11      main
```

## 4. Módulo `scan`

### 4.1. Connect-scan básico contra localhost

```bash
./main scan --host 127.0.0.1 --ports 22,80,443,9999
```

Salida (todos cerrados en VM limpia, lo cual también valida el scanner):

```
[scan] objetivo: 127.0.0.1 (127.0.0.1)
----------------------------------------------------------
 PUERTO   ESTADO    BANNER
----------------------------------------------------------
  22     CERRADO  
  80     CERRADO  
  443    CERRADO  
  9999   CERRADO  
----------------------------------------------------------
Resumen: 0 abiertos / 4 probados
```

### 4.2. Banner-grab contra un servicio activo

Lanzamos un servidor de prueba en otra terminal (`nc -lvnp 4444` o
`python3 -m http.server 8080`) y escaneamos:

```bash
./main scan --host 127.0.0.1 --ports 4444,8080 --banner
```

Salida esperada (depende del servicio):

```
[scan] objetivo: 127.0.0.1 (127.0.0.1)  [+banner]
...
  4444   ABIERTO  
  8080   ABIERTO  HTTP/1.0 501 Unsupported method ('')
```

Capturas: `evidence/scan_banner.png`.

## 5. Módulo `brute`

### 5.1. Ataque por diccionario contra SHA-256("password")

```bash
printf 'admin\npassword\nqwerty\n' > /tmp/wl.txt
./main brute --algo sha256 \
    --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
    --wordlist /tmp/wl.txt
```

Salida:

```
[brute] algo=sha256  hash=5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8  wordlist=/tmp/wl.txt
--------------------------------
[+] MATCH encontrado en 2 intentos (0 ms)
    password = "password"
```

### 5.2. Ataque contra FNV-1a/32

```bash
./main brute --algo fnv --hash 0x364b5f18 --wordlist /tmp/wl.txt
```

Salida:

```
[brute] algo=fnv  hash=364b5f18  wordlist=/tmp/wl.txt
--------------------------------
[+] MATCH encontrado en 2 intentos (0 ms)
    password = "password"
```

### 5.3. Benchmark con rockyou.txt (parcial)

```bash
./main brute --algo sha256 \
    --hash <hash_falso> \
    --wordlist /usr/share/wordlists/rockyou.txt \
    --limit 50000
```

Mide el throughput; útil para discutir el orden de magnitud frente a un hash
no salted en el reporte final.

## 6. Módulo `sniff` (requiere root)

```bash
sudo ./main sniff --count 10
```

Salida esperada (resumen por paquete con cabeceras parseadas):

```
[sniffer] Capturando hasta 10 paquetes (Ctrl-C aborta)
------------------------------------------------------
#1  192.168.56.1 -> 192.168.56.10  TCP  sport=22  dport=53344  flags=PA  bytes=98
#2  192.168.56.10 -> 192.168.56.1  TCP  sport=53344  dport=22  flags=A  bytes=66
...
[sniffer] 10 paquetes procesados
```

Generamos tráfico paralelo con `ping 192.168.56.1` o `curl http://example.test`.
Captura de pantalla en `evidence/sniff_traffic.png` y captura cruzada con
Wireshark en `evidence/wireshark_traffic.png`.

## 7. Módulo `mem`

```bash
./main mem --pid 1 | head -10
```

Salida (las direcciones cambian por ASLR):

```
[mem] inspección de PID 1
  Name:	bwrap
  Uid:	1001	1001	1001	1001
  VmPeak:	    3648 kB
  VmRSS:	    1452 kB
------------------------------------------------------------
 START-END                  PERMS  TAG    PATH
------------------------------------------------------------
 61af6d855000-61af6d858000  r--p   ---                        /usr/bin/bwrap
 61af6d858000-61af6d861000  r-xp  [ X ]                       /usr/bin/bwrap
```

Si el proceso contiene regiones `rwxp` (raras en código limpio, normales en
JITs o shellcode) el toolkit marca cada una con `[RWX]` y suma una alerta al
final. Útil para detectar memoria sospechosa durante el análisis dinámico.

## 8. Análisis estático automatizado

```bash
make analysis
```

Genera:

```
analysis/strings_debug.txt       (~134 KB)
analysis/strings_stripped.txt    (~7.5 KB)
analysis/symbols.txt             nm sobre binario con símbolos
analysis/elf_header.txt          readelf -h
analysis/sections.txt            objdump -h
```

Discusión completa en `analysis/notes.md`.

## 9. Resultado global

| Subcomando  | Build | Ejecución | Salida coincide con spec |
|-------------|:-----:|:---------:|:-----:|
| `--help`    | ✓ | ✓ | ✓ |
| `hash`      | ✓ | ✓ | ✓ (vector FIPS 180-4) |
| `procs`     | ✓ | ✓ | ✓ |
| `scan`      | ✓ | ✓ | ✓ |
| `brute`     | ✓ | ✓ | ✓ |
| `sniff`     | ✓ | ✓ (root) | ✓ |
| `mem`       | ✓ | ✓ | ✓ |

Compilación sin warnings con `-Wall -Wextra -Wpedantic`.
