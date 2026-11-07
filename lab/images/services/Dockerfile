FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      dnsmasq \
      nginx \
      openssh-server \
      openssl \
    && mkdir -p /run/sshd /etc/nginx/certs \
    && ssh-keygen -A \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
      -subj "/CN=services.wqe7002.lab" \
      -keyout /etc/nginx/certs/services.key \
      -out /etc/nginx/certs/services.crt \
    && rm -rf /var/lib/apt/lists/*

COPY dnsmasq.conf /etc/dnsmasq.d/wqe7002.conf
COPY nginx.conf /etc/nginx/sites-available/default
COPY start-services /usr/local/bin/start-services
RUN chmod 0755 /usr/local/bin/start-services

CMD ["/usr/local/bin/start-services"]
