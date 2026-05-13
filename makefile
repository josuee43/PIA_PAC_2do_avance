# =============================================================================
# Makefile — EduSec Toolkit (PIA PAC Ene-Jun 2026 — Segundo Avance)
# -----------------------------------------------------------------------------
# Genera DOS binarios en ./bin/ (requisito de la rúbrica):
#   bin/main-debug   — con símbolos (-g) para análisis estático/dinámico.
#   bin/main         — stripped para entrega y reversing.
# Y copia el stripped en la raíz como ./main para ejecución cómoda.
# =============================================================================

CXX        := g++
COMMON     := -std=c++17 -Wall -Wextra -Wpedantic -Isrc
CXXFLAGS_D := $(COMMON) -O0 -g -ggdb -fno-omit-frame-pointer
CXXFLAGS_R := $(COMMON) -O2 -DNDEBUG
LDFLAGS    :=
STRIP      := strip

SRC_DIR     := src
BUILD_D     := build/debug
BUILD_R     := build/release
BIN_DIR     := bin
TARGET_D    := $(BIN_DIR)/main-debug
TARGET_R    := $(BIN_DIR)/main
TARGET_ROOT := main

SOURCES := $(shell find $(SRC_DIR) -name '*.cpp')
OBJS_D  := $(SOURCES:$(SRC_DIR)/%.cpp=$(BUILD_D)/%.o)
OBJS_R  := $(SOURCES:$(SRC_DIR)/%.cpp=$(BUILD_R)/%.o)

.PHONY: all debug release clean run analysis

all: debug release $(TARGET_ROOT)
	@echo "==> Listo:"
	@echo "    $(TARGET_D)   (con simbolos, para analisis)"
	@echo "    $(TARGET_R)         (stripped, en bin/)"
	@echo "    ./$(TARGET_ROOT)            (copia stripped en raiz, atajo)"

debug:   $(TARGET_D)
release: $(TARGET_R)

$(TARGET_D): $(OBJS_D)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS_D) $^ -o $@ $(LDFLAGS)
	@echo "==> Binario con simbolos: $@"

$(TARGET_R): $(OBJS_R)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS_R) $^ -o $@ $(LDFLAGS)
	$(STRIP) --strip-all $@
	@echo "==> Binario stripped:     $@"

$(TARGET_ROOT): $(TARGET_R)
	@cp $(TARGET_R) $(TARGET_ROOT)
	@echo "==> Copia para ejecucion: ./$@"

$(BUILD_D)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_D) -c $< -o $@

$(BUILD_R)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS_R) -c $< -o $@

run: $(TARGET_ROOT)
	./$(TARGET_ROOT) --help

# Genera artefactos de analisis estatico sobre los binarios.
analysis: $(TARGET_D) $(TARGET_R)
	@mkdir -p analysis
	@strings -a -n 6 $(TARGET_D) > analysis/strings_debug.txt
	@strings -a -n 6 $(TARGET_R) > analysis/strings_stripped.txt
	@nm --defined-only --demangle $(TARGET_D) > analysis/symbols.txt 2>/dev/null || true
	@readelf -h $(TARGET_R) > analysis/elf_header.txt 2>/dev/null || true
	@objdump -h $(TARGET_R) > analysis/sections.txt 2>/dev/null || true
	@echo "==> Tamanos:"
	@wc -c $(TARGET_D) $(TARGET_R)
	@echo "==> SHA-256 de los binarios:"
	@./$(TARGET_R) hash --algo sha256 --file $(TARGET_R)
	@./$(TARGET_R) hash --algo sha256 --file $(TARGET_D)

clean:
	rm -rf build $(BIN_DIR) $(TARGET_ROOT)
	@echo "==> Build limpio"
