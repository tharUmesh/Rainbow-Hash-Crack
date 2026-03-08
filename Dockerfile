FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    g++ \
    libopenmpi-dev \
    openmpi-bin \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src/mpi/mpi_cracker.cpp .

RUN mpicxx -O3 mpi_cracker.cpp -o mpi_cracker -lssl -lcrypto

CMD ["bash"]
