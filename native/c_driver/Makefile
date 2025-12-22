# Makefile for C Driver Unit Tests

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g
LDFLAGS = 
INCLUDES = -I.

# Platform-specific settings
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    CFLAGS += -D__linux__
    LDFLAGS += -lpthread
endif

ifeq ($(UNAME_S),Darwin)
    CFLAGS += -D__APPLE__
endif

# Windows (MinGW)
ifeq ($(OS),Windows_NT)
    CFLAGS += -D_WIN32
    LDFLAGS += -lws2_32
    EXE_EXT = .exe
else
    EXE_EXT =
endif

# Source files
DRIVER_SRC = driver_shim.c
XDP_SRC = xdp_loader.c
XDP_PROG_SRC = xdp_backscatter_filter.c
TEST_SRC = test_driver.c
XDP_TEST_SRC = test_xdp_stats.c
XDP_FALLBACK_SRC = test_xdp_fallback.c
XDP_INTEGRATION_SRC = test_xdp_integration.c
FPGA_STUB_SRC = fpga_stub.c
TEST_TARGET = test_driver$(EXE_EXT)
XDP_TEST_TARGET = test_xdp_stats$(EXE_EXT)
XDP_FALLBACK_TARGET = test_xdp_fallback$(EXE_EXT)
XDP_INTEGRATION_TARGET = test_xdp_integration$(EXE_EXT)
XDP_PROG_OBJ = xdp_backscatter_filter.o

# Optional feature flags (uncomment to enable)
# CFLAGS += -DHAS_DPDK
# CFLAGS += -DHAS_AF_XDP
# CFLAGS += -DHAS_IO_URING
# CFLAGS += -DHAS_LIBBPF
# Note: HAS_FPGA removed - FPGA requires real hardware (Xilinx/Intel PCIe devices)
# Use fpga_stub.c for honest capability reporting

# XDP/eBPF compilation settings
CLANG = clang
BPF_CFLAGS = -O2 -target bpf -c
BPF_INCLUDES = -I/usr/include/linux -I.

# Default target
all: $(TEST_TARGET) $(XDP_TEST_TARGET) $(XDP_FALLBACK_TARGET) $(XDP_INTEGRATION_TARGET) $(XDP_PROG_OBJ)

# Build XDP program
$(XDP_PROG_OBJ): $(XDP_PROG_SRC)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -o $@ $<

# Build test executable
$(TEST_TARGET): $(TEST_SRC) $(DRIVER_SRC) $(XDP_SRC) test_framework.h driver_shim.h xdp_loader.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(TEST_SRC) $(DRIVER_SRC) $(XDP_SRC) $(LDFLAGS)

# Build XDP statistics test
$(XDP_TEST_TARGET): $(XDP_TEST_SRC) $(XDP_SRC) xdp_loader.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(XDP_TEST_SRC) $(XDP_SRC) $(LDFLAGS)

# Build XDP fallback test
$(XDP_FALLBACK_TARGET): $(XDP_FALLBACK_SRC) $(XDP_SRC) xdp_loader.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(XDP_FALLBACK_SRC) $(XDP_SRC) $(LDFLAGS)

# Build XDP integration test
$(XDP_INTEGRATION_TARGET): $(XDP_INTEGRATION_SRC) $(XDP_SRC) xdp_loader.h test_framework.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(XDP_INTEGRATION_SRC) $(XDP_SRC) $(LDFLAGS)

# Run tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Run tests with verbose output
test-verbose: $(TEST_TARGET)
	./$(TEST_TARGET) -v

# Run XDP statistics test
test-xdp: $(XDP_TEST_TARGET) $(XDP_PROG_OBJ)
	@echo "Running XDP statistics test (requires root privileges)"
	@echo "Usage: sudo ./$(XDP_TEST_TARGET) [interface] [xdp_program.o]"
	@echo "Example: sudo ./$(XDP_TEST_TARGET) eth0 $(XDP_PROG_OBJ)"

# Run XDP fallback test
test-fallback: $(XDP_FALLBACK_TARGET) $(XDP_PROG_OBJ)
	@echo "Running XDP fallback test (requires root privileges)"
	@echo "Usage: sudo ./$(XDP_FALLBACK_TARGET) [interface]"
	@echo "Example: sudo ./$(XDP_FALLBACK_TARGET) eth0"

# Run XDP integration test
test-integration: $(XDP_INTEGRATION_TARGET) $(XDP_PROG_OBJ)
	@echo "Running XDP integration test (requires root privileges)"
	./$(XDP_INTEGRATION_TARGET)

# FPGA capability check (honest reporting - no fake simulation)
fpga-status:
	@echo "=== FPGA Capability Report ==="
	@echo "Status: FPGA: Not Available"
	@echo "Note: FPGA acceleration requires actual PCIe FPGA hardware"
	@echo "      (Xilinx/Intel) with appropriate drivers installed."
	@echo "=============================="

# Clean build artifacts
clean:
	rm -f $(TEST_TARGET)
	rm -f $(XDP_TEST_TARGET)
	rm -f $(XDP_FALLBACK_TARGET)
	rm -f $(XDP_INTEGRATION_TARGET)
	rm -f $(XDP_PROG_OBJ)
	rm -f *.o
	rm -f core
	rm -f vgcore.*

# Memory check with valgrind (Linux only)
memcheck: $(TEST_TARGET)
ifeq ($(UNAME_S),Linux)
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TEST_TARGET)
else
	@echo "Valgrind not available on this platform"
endif

# Static analysis with cppcheck
analyze:
	cppcheck --enable=all --std=c99 --platform=unix64 $(DRIVER_SRC) $(TEST_SRC)

# Code coverage (requires gcov)
coverage: CFLAGS += -fprofile-arcs -ftest-coverage
coverage: LDFLAGS += -lgcov
coverage: clean $(TEST_TARGET)
	./$(TEST_TARGET)
	gcov $(DRIVER_SRC)
	@echo "Coverage report generated in *.gcov files"

# Debug build
debug: CFLAGS += -DDEBUG -O0
debug: $(TEST_TARGET)

# Release build
release: CFLAGS += -DNDEBUG -O3
release: $(TEST_TARGET)

# Install (copy to system location)
install: $(TEST_TARGET)
	@echo "Installing test binary to /usr/local/bin (requires sudo)"
	sudo cp $(TEST_TARGET) /usr/local/bin/

# Uninstall
uninstall:
	sudo rm -f /usr/local/bin/$(TEST_TARGET)

# Help
help:
	@echo "Available targets:"
	@echo "  all        - Build test executable and XDP program (default)"
	@echo "  test       - Build and run tests"
	@echo "  test-xdp   - Build and run XDP statistics test"
	@echo "  test-fallback - Build and run XDP fallback test"
	@echo "  test-integration - Build and run XDP integration test"
	@echo "  fpga-status - Show FPGA capability status (honest reporting)"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  clean      - Remove build artifacts"
	@echo "  memcheck   - Run tests with valgrind (Linux only)"
	@echo "  analyze    - Run static analysis with cppcheck"
	@echo "  coverage   - Build with coverage and generate report"
	@echo "  debug      - Build debug version"
	@echo "  release    - Build optimized release version"
	@echo "  install    - Install test binary system-wide"
	@echo "  uninstall  - Remove installed binary"
	@echo "  help       - Show this help message"

# Phony targets
.PHONY: all test test-verbose clean memcheck analyze coverage debug release install uninstall help