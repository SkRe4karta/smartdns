ARG BASE
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN apt-get update && apt-get install -y systemd systemd-sysv dbus python3 python3-venv ca-certificates openssl curl iproute2 nftables nginx haproxy certbot dnsutils docker.io && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
