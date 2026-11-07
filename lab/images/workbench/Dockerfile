FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      iproute2 \
      iputils-ping \
      nmap \
      python3 \
      python3-pip \
      tcpdump \
    && python3 -m pip install --break-system-packages --no-cache-dir scapy==2.7.0 \
    && rm -rf /var/lib/apt/lists/*

COPY doctor /opt/course-lab/doctor
COPY capture-start /opt/course-lab/capture-start
COPY capture-stop /opt/course-lab/capture-stop
RUN chmod 0755 /opt/course-lab/doctor /opt/course-lab/capture-start /opt/course-lab/capture-stop \
    && mkdir -p /evidence

CMD ["sleep", "infinity"]
