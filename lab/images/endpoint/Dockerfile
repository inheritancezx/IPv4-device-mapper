FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping python3 \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
