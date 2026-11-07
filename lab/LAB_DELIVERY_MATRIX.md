# WQE7002 lab delivery matrix

This is the operational delivery plan for the reusable course lab. It deliberately separates code-development convenience from the source of assessed evidence.

## Delivery modes

| Mode | Meaning |
|---|---|
| Browser/Moodle | No local network environment is required. |
| Local Compose | A group runs the supplied three-container topology on one member's laptop. The `lab` network is internal and no service ports are published to the host LAN. |
| Central fallback | The lecturer-operated three-VM pod provides the same roles when Local Compose is unsupported or an activity requires validated Layer-2/DHCP behaviour. |
| External API | The task is bounded by the service's API policy rather than the course topology. |

## Topic and assessment map

| Course element | Primary mode | Central fallback / authority | Reason |
|---|---|---|---|
| Topics 1–2, Quiz 1 | Browser/Moodle | None | Programming and networking foundations do not need live packet transmission. |
| Topic 3: Scapy | Local Compose | Central fallback | Students construct packets and inspect authorised local traces. |
| Topic 4: Nmap | Local Compose | Central fallback | The `services` container supplies the defined scan target. |
| Assignment 1 | Local Compose rehearsal; central pod for measured run until acceptance testing is complete | Central fallback is authoritative initially | The group needs a known capture point, a completed scope and repeatable reset. |
| Topic 5: Shodan | External API | Recovery evidence bundle | Passive Internet-index work is not a Docker topology task. |
| Topic 6: ARP spoofing | Local Compose after compatibility acceptance | Central fallback | The workbench, endpoint and services roles share one internal Layer-2 bridge. |
| Topic 7: DHCP starvation | Central fallback initially | Central fallback | Docker Desktop DHCP and raw-Ethernet behaviour must be proven on supported platforms before it becomes student-authoritative. |
| Topic 8: DHCP spoofing and poisoning | Central fallback initially | Central fallback | Requires the same DHCP compatibility and capture-vantage validation as Topic 7. |
| Topic 9: traffic classification | Local Compose | Central fallback | Workbench-originated PCAPs are enough for initial feature work; the central pod supplies a common reference trace. |
| Topic 10: adversary emulation with GANs | Local Compose or local Python | Shared compute only if needed | This is an analysis workload, not a Layer-2 lab. |
| Assignment 2 | Local Compose | Central fallback | The deliverable should be reproducible from a pinned project bundle. |
| Topic 11: SOAR playbooks | Local Compose | Central fallback | A small local webhook/playbook stack is appropriate; do not require an enterprise SIEM. |
| Topic 12 and final project | Local Compose or approved equivalent | Central fallback for demonstrations | Students submit a reproducible artefact and evidence rather than a persistent personal VM. |

## Practical decision

Start with one central three-VM pod and this Local Compose bundle. A group develops on a single member's laptop, then uses one booked central-lab slot for any activity that requires instructor-verifiable evidence. After acceptance tests pass on the supported local platforms, Assignment 1 may accept Local Compose evidence under the same scope and provenance rules.

No student receives a dedicated VM. The central fallback has only three role VMs: `workbench`, `endpoint` and `services`. The hypervisor captures packets and resets the pod.

## Acceptance criteria for Local Compose evidence

Before it becomes an assessed evidence source, the lecturer must confirm on each supported platform:

1. the bundle has no published ports and the lab containers cannot reach an external address;
2. Scapy can transmit and observe an ARP request/reply wholly inside the internal bridge;
3. Nmap can produce XML against the declared services container and cannot scan a target outside its manifest;
4. the workbench can record a PCAP of its own authorised probe/reply exchange;
5. `reset` removes run state and restores the declared addresses and services; and
6. the same commands work on an Apple Silicon Mac, an Intel/AMD host and the university fallback host.

DHCP Topics 7–8 have two extra criteria: the actual client must obtain and release leases from the lab DHCP service, and the capture point must record the expected DHCP messages. Until that is demonstrated, use the central pod for those topics.
