# BUILD LAYER
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    make \
    libjudy-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/pcfg
COPY . .
RUN make

# RUNTIME LAYER
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjudy1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/pcfg/pcfg /usr/local/bin/pcfg

WORKDIR /data

ENTRYPOINT ["pcfg"]
