FROM alpine:3.23 AS builder

RUN apk add --no-cache \
    cmake \
    ninja \
    g++ \
    git \
    gmp-dev \
    openssl-dev

WORKDIR /app

COPY . .

RUN cmake -S . -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build

FROM alpine:3.23 AS test

RUN apk add --no-cache \
    cmake \
    gmp-dev \
    openssl-dev

WORKDIR /app

COPY --from=builder /app/build ./build
COPY --from=builder /app/cryptography/cryptography_tests ./cryptography/cryptography_tests

CMD ["ctest", "--test-dir", "build", "--output-on-failure"]

FROM alpine:3.23 AS runtime

RUN apk add --no-cache \
    libstdc++ \
    libgcc \
    gmp-dev \
    openssl

WORKDIR /app

COPY --from=builder /app/cryptography/cryptography ./cryptography

CMD ["./cryptography"]
