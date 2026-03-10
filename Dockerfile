FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libboost-system-dev \
    libboost-thread-dev \
    libboost-log-dev \
    libboost-filesystem-dev \
    libboost-program-options-dev \
    iproute2 \
    net-tools \
    iputils-ping \
    python3 \
    python3-scapy \
    python3-pip \
    tcpdump \
    && pip3 install debugpy \
    && rm -rf /var/lib/apt/lists/*

# Install vsomeip
WORKDIR /opt
RUN git clone https://github.com/COVESA/vsomeip.git && \
    cd vsomeip && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig

FROM base AS builder

WORKDIR /app
COPY src/ /app/src/
WORKDIR /app/src
RUN mkdir build && cd build && \
    cmake .. && \
    make radio_service radio_client

FROM base AS server
WORKDIR /app
COPY --from=builder /app/src/build/radio_service /app/
COPY server/radio-service.json /app/
COPY server/entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]

FROM base AS client
WORKDIR /app
COPY --from=builder /app/src/build/radio_client /app/
COPY client/radio-client.json /app/
COPY client/entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]

FROM base AS attacker
WORKDIR /app
# Copy the attacker scripts we moved earlier
COPY attacker/ /app/
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
