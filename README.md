# HPC Password Cracker — Group 17
EE7218 / EC7207 – High Performance Computing

Parallel brute-force SHA-256 hash recovery using POSIX Threads, MPI, and Hybrid MPI+CUDA, with Rainbow Table precomputation.

## Group Members
| ID | Name |
|---|---|
| EG/2021/4500 | Dulkith G.L.M. |
| EG/2021/4502 | Edirisinghe E.A.T.U.G. |
| EG/2021/4507 | Fernando H.T. |

## Project Structure
```
hpc_password_cracker/
├── bin/                  # Compiled executables (git-ignored)
├── docs/                 # Proposal, Guidelines, Analysis Report
├── include/
│   └── common.h          # Shared: CHARSET, sha256(), validation helpers
├── scripts/
│   └── benchmark.sh      # Automated timing sweep → results CSV
├── src/
│   ├── serial/           # Deliverable 1: Serial baseline
│   ├── pthreads/         # Deliverable 2: Shared memory (POSIX Threads)
│   ├── mpi/              # Deliverable 3: Distributed memory (MPI)
│   ├── hybrid/           # Deliverable 4: Hybrid MPI + CUDA
│   └── rainbow/          # Rainbow table generation & lookup
├── Makefile
├── README.md
└── .gitignore
```

## Prerequisites
- GCC ≥ 9 with C++17 support
- OpenSSL 3.x (`libssl-dev`)
- OpenMPI (`libopenmpi-dev`, `openmpi-bin`)
- CUDA Toolkit ≥ 11 (for hybrid target)
- POSIX threads (included with GCC on Linux)

## Building

```bash
# All targets
make all

# Individual targets
make serial
make pthreads
make mpi
make hybrid

# Clean
make clean
```

## Running

### Serial
```bash
./bin/serial_cracker <length> <sha256_hash>
# Example:
./bin/serial_cracker 3 $(echo -n "ab3" | sha256sum | cut -d' ' -f1)
```

### POSIX Threads
```bash
./bin/pthreads_cracker <length> <sha256_hash> <num_threads>
# Example:
./bin/pthreads_cracker 3 <hash> 8
```

### MPI
```bash
mpirun -np <num_processes> ./bin/mpi_cracker <length> <sha256_hash>
# Example:
mpirun -np 4 ./bin/mpi_cracker 3 <hash>
```

### Hybrid (MPI + CUDA)
```bash
mpirun -np <num_processes> ./bin/hybrid_cracker <length> <sha256_hash>
```

## Benchmarking
```bash
chmod +x scripts/benchmark.sh
./scripts/benchmark.sh <password> <length>
# Results saved to results/benchmark_<timestamp>.csv
```

## Notes
- All implementations use the same charset: `abcdefghijklmnopqrstuvwxyz0123456789`
- Target hash must be a valid 64-character lowercase hex SHA-256 string
- The serial implementation is the correctness and timing baseline
