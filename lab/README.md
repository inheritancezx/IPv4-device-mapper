# WQE7002 local course lab

This is a three-role Docker Compose topology for an individual WQE7002 student. It is designed for local practice in Topics 3–4, Assignment 1 rehearsal, ARP work after compatibility acceptance, traffic-classification data collection, and later reproducible defensive-computing exercises.

It is not connected to the default Docker network, publishes no ports, does not use host networking, and does not mount the Docker socket. `workbench` has only `NET_RAW`, which permits Scapy, Nmap SYN scans and tcpdump from the student workstation container. The provided bundle does not use `privileged: true`.

## Prerequisites

- Docker Engine or Docker Desktop with Compose v2.
- At least 6 GB free RAM and 8 GB free disk space.
- A supported Linux, Windows/WSL2, Intel macOS or Apple Silicon macOS platform.

Do not use `network_mode: host`, `macvlan`, `ipvlan`, extra networks, published ports or a Docker socket mount. Those changes invalidate the course boundary.

## Start an individual lab

From this directory, choose an individual label and build the local images:

```bash
docker compose --project-name wqe7002-s1234567 up --build -d
docker compose --project-name wqe7002-s1234567 exec workbench /opt/course-lab/doctor
docker compose --project-name wqe7002-s1234567 exec workbench bash
```

Inside `workbench`, the declared services are at:

```text
endpoint  172.28.70.3
services  172.28.70.10
```

The student runs their Assignment 1 program only against one of the completed standard scopes mounted under `/scopes`. It stores its PCAP, JSON, Nmap XML and checksums in `/evidence`.

## Standard Assignment 1 scopes

Every student receives the same contained topology and may choose either pathway:

```bash
docker compose --project-name wqe7002-s1234567 exec workbench cat /scopes/assignment-01-device-map.json
docker compose --project-name wqe7002-s1234567 exec workbench cat /scopes/assignment-01-tcp-syn-scan.json
```

Do not edit or replace these files. Option A uses `assignment-01-device-map.json`; Option B uses `assignment-01-tcp-syn-scan.json`. They are read-only inside `workbench` and name the only permitted network, target and ports. The `scripts/create_scope.py` helper is retained for instructor testing, not student assessment setup.

The standard local environment becomes an assessed evidence source only when the lecturer announces Local Compose acceptance in Spectrum. Until then, use the equivalent central fallback.

## Capture from the authorised workstation vantage point

In one terminal:

```bash
docker compose --project-name wqe7002-s1234567 exec workbench /opt/course-lab/capture-start assignment-01.pcap
```

In another, run the group's authorised task. Stop capture with:

```bash
docker compose --project-name wqe7002-s1234567 exec workbench /opt/course-lab/capture-stop
```

The PCAP appears in `evidence/`. It records the workbench's own packet exchange; it is not represented as an omniscient network capture.

## Reset

```bash
./scripts/reset.sh wqe7002-s1234567
```

This removes only this Compose project's containers, volumes and generated run evidence. Copy required evidence out first.

## DHCP limitation

The services image includes `dnsmasq` so later DHCP configurations can be developed in one place. The current Compose topology gives containers static Docker-assigned addresses, so it is not yet the authoritative DHCP client/server environment for Topics 7–8. Use the central fallback for those experiments until the dedicated DHCP acceptance tests have passed.

See `LAB_DELIVERY_MATRIX.md` for the activity-by-activity decision.
