FROM ubuntu:24.04 AS builder

RUN apt update && apt install -y \
    cmake \
    ninja-build \
    g++ \
    git \
    libgmp-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build

FROM ubuntu:24.04 AS test

RUN apt update && apt install -y \
    cmake \
    libgmp10 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/build ./build
COPY --from=builder /app/cryptography/cryptography_tests ./cryptography/cryptography_tests

CMD ["ctest", "--test-dir", "build", "--output-on-failure"]

FROM ubuntu:24.04 AS runtime

RUN apt update && apt install -y \
    libgmp10 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/cryptography/cryptography ./cryptography

CMD ["./cryptography"]
