# Multi-stage Dockerfile for HexPress v6
FROM alpine:3.19 AS builder
RUN apk add --no-cache build-base clang compiler-rt
WORKDIR /src
COPY . .
# No -march flag on purpose: AVX2 is selected at run time (CPU dispatch), so one image runs everywhere.
RUN clang++ -O3 -std=c++17 -pthread hex-press.cpp libhexpress.cpp -o /src/hex-press && \
    clang++ -O3 -std=c++17 -pthread hex-tract.cpp libhexpress.cpp -o /src/hex-tract && \
    clang++ -O3 -std=c++17 -pthread -fPIC -shared libhexpress.cpp -o /src/libhexpress.so

FROM alpine:3.19 AS runner
RUN apk add --no-cache libstdc++
WORKDIR /app
COPY --from=builder /src/hex-press /usr/local/bin/hex-press
COPY --from=builder /src/hex-tract /usr/local/bin/hex-tract
COPY --from=builder /src/libhexpress.so /usr/local/lib/libhexpress.so
ENV LD_LIBRARY_PATH=/usr/local/lib
ENTRYPOINT ["/usr/local/bin/hex-press"]
CMD ["--help"]
