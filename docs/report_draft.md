# Reporte técnico — Segundo avance PIA
## EduSec Toolkit — Grupo 01

> Borrador técnico (Fase IV — Desarrollo Ofensivo Responsable). Documento de
> trabajo: 2–3 páginas estimadas, sujeto a ampliación para el reporte final.

---

## 1. Descripción del payload / componente

`EduSec Toolkit` es un binario CLI en C++17 — no es un *payload* en el sentido
ofensivo clásico: es un **toolkit educativo modular**, ético y autocontenido,
diseñado para servir como objetivo de análisis estático y dinámico durante el
PIA. El binario no es persistente, no exfiltra datos, no escala privilegios
solo; opera de manera benigna dentro de la VM aislada del equipo.

Los seis subcomandos cubren técnicas que aparecen sistemáticamente en
post-explotación / reconocimiento durante un *pentest* real:

| Subcomando | Técnica de ciberseguridad                       | Fase del PIA |
|------------|--------------------------------------------------|--------------|
| `hash`     | Hashing FNV-1a/32 y SHA-256 (FIPS 180-4 puro)    | II           |
| `brute`    | Ataque por diccionario contra FNV/SHA-256        | II           |
| `procs`    | Enumeración local de procesos via `/proc`        | III          |
| `scan`     | TCP connect-scan + banner-grabbing               | II           |
| `sniff`    | Captura pasiva con raw sockets (`AF_PACKET`)     | II           |
| `mem`      | Inspección de `/proc/<pid>/maps` (RWX hunting)   | III          |

## 2. Diseño técnico

### 2.1. Arquitectura

`src/main.cpp` instancia un *dispatcher* mínimo: recibe `argv[1]`, empaqueta
el resto de argumentos en un `std::vector<std::string>` y los delega a una
función `run(args)` en el módulo correspondiente, cada uno aislado en
`src/modules/`. Todos los módulos comparten la misma firma para mantener un
acoplamiento de interfaz uniforme.

```
main → switch(sub) → modules/<name>::run(args)
                     │
                     ├── hash_module   (FNV + SHA-256)
                     ├── bruteforce    (dict attack)
                     ├── proc_module   (/proc enum)
                     ├── netscan       (TCP + banner)
                     ├── sniffer       (AF_PACKET raw)
                     └── mem_module    (/proc maps)
```

### 2.2. Decisiones de diseño

- **C++17 puro y POSIX**: sin OpenSSL, sin libpcap. Esto facilita el análisis
  estático posterior (no hay simbología de librerías terceras opacando el
  binario) y maximiza la reproducibilidad en cualquier Linux moderno.
- **SHA-256 manual**: la implementación de `sha256.{h,cpp}` sigue FIPS 180-4
  literalmente. Las constantes `K[64]` y `H0[8]` viven en `.rodata` y son
  reconocibles como firma en el binario stripped — esto es **intencional**
  para el ejercicio de reversing.
- **Compilación con dos perfiles**:
  - `bin/main-debug`  — `-O0 -g -ggdb` → análisis con símbolos.
  - `bin/main`        — `-O2 -DNDEBUG` → `strip --strip-all`.
- **Sockets no bloqueantes con `select()`**: en `netscan`. Permite imponer
  timeouts cortos sin lanzar threads — útil para mantener el grafo de
  llamadas simple en Ghidra.

### 2.3. Dependencias

Únicamente la libc estándar de GNU y cabeceras POSIX/Linux:
`<sys/socket.h>`, `<arpa/inet.h>`, `<netdb.h>`, `<sys/select.h>`,
`<linux/if_ether.h>`, `<netinet/{ip,tcp,udp}.h>`, `<dirent.h>`.

## 3. Pruebas realizadas (Fase II–III)

Pruebas reproducibles documentadas en `docs/tests.md` (comandos exactos y
outputs reales). Resumen:

1. **Vector de prueba SHA-256.** `hash --algo sha256 --string "abc"` produce
   `ba7816bf...015ad`, coincidente con FIPS 180-4 Apéndice B.1. → la
   implementación es funcionalmente correcta.
2. **Ataque por diccionario.** `brute --algo sha256` recupera la palabra
   `"password"` desde un diccionario de tres entradas en `0 ms`, demostrando
   la viabilidad del ataque contra hashes sin sal.
3. **Reconocimiento TCP.** `scan --host 127.0.0.1 --ports 22,80,443,9999`
   confirma 0 puertos abiertos en la VM limpia — validación negativa.
4. **Banner-grab.** Contra `python3 -m http.server 8080`, el banner
   capturado coincide con el banner HTTP de la librería estándar de Python.
5. **Sniffer.** Con `sudo ./main sniff --count 10` y tráfico paralelo,
   se observan tramas TCP/UDP/ICMP parseadas correctamente.
6. **Inspección de memoria.** `mem --pid 1` lista regiones de `init`/`bwrap`
   con sus permisos y marca correctamente las regiones de código (`r-xp`).

## 4. Hallazgos iniciales del análisis estático

Documento completo en `analysis/notes.md`. Hallazgos preliminares:

1. **Tipo ELF64 PIE** con ASLR habilitado. NX en `.text`. Falta CET
   (`-fcf-protection=full`) — se anotó como mejora futura.
2. **Tamaño efectivo** del binario stripped: ~67 KB. Compresión efectiva del
   stripping: 88.2% (de 576 KB a 67 KB).
3. **`strings` sobre stripped revela toda la superficie CLI** (`--algo`,
   `--ports`, `--wordlist`, `--banner`, etc.). En un payload real estos
   strings se cifrarían o se construirían en runtime. Como toolkit educativo
   se deja como demostración del costo de no ofuscar.
4. **Ausencia de IoCs de red maliciosos.** `grep -iE 'http://|https://|wget|
   nc -e|/bin/sh'` sobre los strings devuelve 0 resultados → coherente con
   el alcance benigno declarado.
5. **Las constantes K[64] de SHA-256 sobreviven al strip** intactas en
   `.rodata`. Cualquier reverser experimentado las identifica en segundos.

## 5. Riesgos y mitigaciones

| Riesgo                                                            | Mitigación implementada en este avance |
|-------------------------------------------------------------------|-----------------------------------------|
| Uso del toolkit fuera de la VM (escaneo a redes ajenas)           | Bloqueo organizacional: VMs en host-only; documentación explícita en README |
| `sniff` requiere `CAP_NET_RAW`; ejecución como root               | Detección de `errno` en `socket()` y mensaje claro; **no** se setea `setuid` ni se usa `setcap` |
| `brute` puede usarse para crackear hashes ajenos                  | Solo opera contra hash y diccionario provistos por el operador; no descarga de internet |
| Filtración del binario a equipos no autorizados                   | El binario no realiza acciones destructivas ni persistencia, por diseño |
| Vulnerabilidades en parseo (overflow en `parse_ports`, etc.)      | Compilación con `-Wall -Wextra -Wpedantic`; uso de `std::string`/`std::vector` (no buffers crudos); validación de rangos (`1..65535`) |
| Lectura de `/proc/<pid>/mem` (escalada)                           | **No implementado** intencionalmente — `mem_module` solo lee `maps`/`status` |
| Posibles falsos positivos en deteccion `[RWX]`                    | Anotación textual; no acción automática |

## 6. Trabajo pendiente (hacia el reporte final)

- **Análisis dinámico** con `strace -f` y `ltrace` para los seis subcomandos,
  documentando syscalls relevantes.
- **Ingeniería inversa formal** del binario stripped en Ghidra/Radare2,
  con grafo de llamadas y comparación cruzada con `bin/main-debug`.
- **Endurecimiento** del binario final: `-fstack-protector-strong`,
  `-D_FORTIFY_SOURCE=2`, `-fcf-protection=full`, `-Wl,-z,now -Wl,-z,relro`.
- **Banner-grab activo**: enviar probes específicos (HTTP `HEAD`, SMTP `HELO`)
  para puertos que no emiten banner pasivo.
- **`sniff` con filtros BPF** vía `setsockopt(SO_ATTACH_FILTER)` para reducir
  ruido en redes activas.
- **Reporte final 5–8 páginas** con conclusiones y métricas comparativas
  (FNV vs SHA-256 — H/s, coste ASIC, etc.).
- **CMake** opcional para portar la compilación a sistemas donde `make` no
  sea estándar.

## 7. Conclusión preliminar

El segundo avance entrega un toolkit con **seis módulos funcionales**, **dos
variantes de binario** (debug/stripped), **pruebas reproducibles** con
vectores de validación oficial (FIPS 180-4) y **artefactos de análisis
estático** generados automáticamente. La arquitectura modular y el uso
exclusivo de la librería estándar facilitan tanto la auditoría del código
fuente como el reversing del binario, cumpliendo con el doble propósito
educativo de la materia: aprender a construir y aprender a desmontar.

---

_Equipo: Grupo 01 — Josue Arcos · Johan Garay · Andrea Abundiz._
_Versión del binario: `0.2.0-avance2` · Tag git: `pia-avance-2`._
