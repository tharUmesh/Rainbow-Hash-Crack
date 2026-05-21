# ─────────────────────────────────────────────────────────────────────────────
#  HPC Password Cracker — Master Makefile
#  Targets: serial | pthreads | mpi | hybrid | all | clean
# ─────────────────────────────────────────────────────────────────────────────

CXX      := g++
NVCC     := nvcc
MPICC    := mpicxx

CXXFLAGS := -O2 -std=c++17 -Wall -Wextra -I./include
LDFLAGS  := -lssl -lcrypto              # OpenSSL

BINDIR   := bin
SRCDIR   := src

# ── Output executables ────────────────────────────────────────────────────────
SERIAL_BIN   := $(BINDIR)/serial_cracker
PTHREADS_BIN := $(BINDIR)/pthreads_cracker
MPI_BIN      := $(BINDIR)/mpi_cracker
HYBRID_BIN   := $(BINDIR)/hybrid_cracker

.PHONY: all serial pthreads mpi hybrid clean

all: serial pthreads mpi hybrid

# ── 1. Serial ─────────────────────────────────────────────────────────────────
serial: $(SERIAL_BIN)

$(SERIAL_BIN): $(SRCDIR)/serial/serial_cracker.cpp include/common.h | $(BINDIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)
	@echo "[OK] Built: $@"

# ── 2. POSIX Threads ─────────────────────────────────────────────────────────
pthreads: $(PTHREADS_BIN)

$(PTHREADS_BIN): $(SRCDIR)/pthreads/pthreads_cracker.cpp include/common.h | $(BINDIR)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS) -lpthread
	@echo "[OK] Built: $@"

# ── 3. MPI ────────────────────────────────────────────────────────────────────
mpi: $(MPI_BIN)

$(MPI_BIN): $(SRCDIR)/mpi/mpi_cracker.cpp include/common.h | $(BINDIR)
	$(MPICC) $(CXXFLAGS) $< -o $@ $(LDFLAGS)
	@echo "[OK] Built: $@"

# ── 4. Hybrid (MPI + CUDA) ───────────────────────────────────────────────────
hybrid: $(HYBRID_BIN)

$(HYBRID_BIN): $(SRCDIR)/hybrid/hybrid_cracker.cu include/common.h | $(BINDIR)
	$(NVCC) -O2 -std=c++17 -I./include $< -o $@ $(LDFLAGS) -lmpi
	@echo "[OK] Built: $@"

# ── Ensure bin/ exists ────────────────────────────────────────────────────────
$(BINDIR):
	mkdir -p $(BINDIR)

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	rm -f $(BINDIR)/*
	@echo "[OK] bin/ cleaned"
