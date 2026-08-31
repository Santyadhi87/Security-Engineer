
# Secure Network Architecture
**TryHackMe — Security Engineer Path | Module 3**  
**Room:** [Secure Network Architecture](https://tryhackme.com/room/introtosecurityarchitecture)

---

## Table of Contents
- [Task 1 — Introduction](#task-1--introduction)
- [Task 2 — The Need for Secure Segmentation](#task-2--the-need-for-secure-segmentation)
- [Task 3 — Security Zones](#task-3--security-zones)
- [Task 4 — Traffic Filtering and ACLs](#task-4--traffic-filtering-and-acls)
- [Task 5 — Firewalls and Zone-Pairs](#task-5--firewalls-and-zone-pairs)
- [Task 6 — SSL/TLS Inspection](#task-6--ssltls-inspection)
- [Task 7 — DHCP Snooping and Dynamic ARP Inspection](#task-7--dhcp-snooping-and-dynamic-arp-inspection)
- [Task 8 — Conclusion](#task-8--conclusion)

---

## Task 1 — Introduction

A network is not just about connecting devices and letting them communicate — it is about designing it securely from the start. The three core principles that separate a functional network from a well-designed one are **redundancy** (if one part fails, traffic reroutes automatically with no downtime), **segmentation** (if one device or server is compromised, it cannot freely move around and access everything else on the network), and **threat awareness** (even after all best practices are applied, understanding what attacks can still occur remains essential). The difference between a network that simply "works" and one that is genuinely well-designed comes down to whether security was considered at every layer of how it was built.

### Learning Objectives

1. Understand the principles of secure network architecture design
2. Learn and implement common network security concepts and protocols
3. Understand a network's environment and potential threats

---

## Task 2 — The Need for Secure Segmentation

### Key Terminology

| Term | One-Line Definition |
|------|-------------------|
| **Network** | A collection of connected devices that can communicate and share data with each other. |
| **Networking** | The practice of designing, building, and managing the connections and communication between devices. |
| **Network Segmentation** | Dividing a network into smaller, isolated sections so that a breach in one section cannot spread to others. |
| **Subnet** | A logically divided portion of a larger network, defined by an IP address range, used to organise and route traffic. |
| **VLAN (Virtual LAN)** | A Layer 2 method of segmenting devices on the same physical switch into separate, isolated logical networks using tags. |
| **802.1q Tag** | A standardised label added to a network frame that identifies which VLAN the traffic belongs to. |
| **Native VLAN** | A special VLAN that handles any traffic passing through a switch that has not been tagged. |
| **Trunk** | A single network link between a switch and a router that carries traffic from multiple VLANs simultaneously. |
| **ROAS (Router on a Stick)** | A routing design where one physical router interface handles traffic for multiple VLANs through a single trunk connection. |
| **Sub-interface** | A virtual interface created on a router to handle traffic for a specific VLAN, defined as `<name>.<vlan-id>`. |
| **BYOD (Bring Your Own Device)** | A practice where employees or clients connect their personal devices to a corporate network, introducing security risks. |
| **RAT (Remote Access Trojan)** | Malware that gives an attacker remote control over an infected device, often used to move through a network and steal data. |
| **Switch** | A network device that connects devices within the same network and forwards traffic based on MAC addresses. |
| **Router** | A network device that forwards traffic between different networks or VLANs based on IP addresses. |

---

### Why Subnets Are Not Enough

Subnetting alone does not fully secure a network. A common real-world scenario is **BYOD (Bring Your Own Device)**, where a client connects an infected device to the network. If that device carries a **Remote Access Trojan (RAT)**, it can freely traverse the network and exfiltrate sensitive data — because subnetting places no restriction on where a device can connect, as long as a valid route exists. The solution to this problem is **VLANs**.

---

### What is a VLAN?

A **VLAN (Virtual LAN)** segments portions of a network at **Layer 2** and differentiates devices without requiring physical separation. VLANs are configured on a switch by adding a **tag** to each frame using the **802.1q (dot1q)** standard, which identifies which VLAN the traffic originated from. Because 802.1q is a vendor-neutral standard, switches and routers from different manufacturers (e.g. Cisco switches with Juniper routers) can all read and process tagged frames consistently.

---

### Key VLAN Concepts

| Concept | Description |
|---------|-------------|
| **802.1q Tag** | A standardised tag added to a frame identifying its VLAN |
| **Native VLAN** | Handles untagged traffic passing through a switch |
| **Trunk** | A single connection between a switch and router carrying multiple VLANs |
| **ROAS (Router on a Stick)** | A design where all VLANs route through one trunk to a single router interface |
| **Sub-interface** | A virtual interface on a router, one per VLAN, defined as `<name>.<vlan-id>` |

---

### Configuring VLANs (Open vSwitch)

```bash
# View current switch configuration
ovs-vsctl show

# Assign a VLAN tag to an interface
ovs-vsctl set port <interface> tag=<0-99>

# Configure a Native VLAN for untagged traffic
ovs-vsctl set port eth0 tag=10 vlan_mode=native-untagged

# Add a trunk (bridge) between switch and router
ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth0 tag=10
```

---

### Routing Between VLANs (VyOS Router)

```bash
# Create a virtual sub-interface for VLAN 10
set interfaces ethernet eth0 vif 10 description 'VLAN 10'
set interfaces ethernet eth0 vif 10 address '192.168.100.1/24'
```

---

### Important Limitation

VLANs provide **physical isolation**, but as long as a route exists between two VLANs, any device can still communicate across them — meaning there is **no true security boundary** without additional controls. This leads to the next concept: **secure VLAN design and network zoning**.

---

### Key Takeaway

VLANs are a powerful segmentation tool, but they are not a complete security solution on their own. Proper VLAN design must be paired with access controls and zoning to truly restrict what devices can reach sensitive systems — directly relevant to Pathfinder, where student devices should never be able to reach agent or admin systems even if they share the same physical network.

---

### Questions

| Question | Answer |
|----------|--------|
| How many trunks are present in this configuration? | 4 |
| What is the VLAN tag ID for interface eth12? | *(check interface config snippet)* |

---

## Task 3 — Security Zones

### Key Terminology

| Term | One-Line Definition |
|------|-------------------|
| **Security Zone** | A defined segment of a network that groups devices or users by trust level and controls how traffic flows in and out. |
| **External Zone** | Any device or entity that exists outside the organisation's network and asset control. |
| **DMZ (Demilitarized Zone)** | A buffer zone that separates untrusted external devices from internal network resources. |
| **Trusted Zone** | An internal network segment containing devices that handle non-sensitive, general business operations. |
| **Restricted Zone** | A high-security segment reserved for critical servers and sensitive databases that require strict access control. |
| **Management Zone** | A segment dedicated to devices and services that manage or administer the network infrastructure. |
| **Audit Zone** | A segment dedicated to security monitoring and telemetry tools such as SIEM systems. |
| **Traffic Rule** | A defined policy that determines what resources a device or user can access based on identifiers like IP or MAC address. |
| **Access Control** | A security mechanism that enforces traffic rules and determines who or what can communicate with a given resource. |
| **Security Policy** | A company-defined set of rules and requirements that governs how network access and permissions are managed. |
| **SIEM** | Security Information and Event Management — a system that collects and analyses security logs and alerts in real time. |
| **Compliance** | Adherence to legal or regulatory standards that dictate how data and network access must be controlled and audited. |
| **Network Architect** | A professional responsible for designing the structure, layout, and security of a network. |

---

### Overview

With VLANs introduced as a segmentation tool, network architecture must now treat security as a core design requirement alongside optimisation and redundancy — not an afterthought. The way VLANs are properly enforced as security boundaries is through **security zones**, which define what devices or users belong in a VLAN and how traffic is permitted to flow in and out of it.

---

### Security Zone Table

| Zone | Explanation | Examples |
|------|-------------|---------|
| **External** | All devices and entities outside the organisation's network or asset control. | Devices connecting to a public web server |
| **DMZ (Demilitarized Zone)** | Separates untrusted networks or devices from internal resources. | BYOD devices, remote users, guests, public servers |
| **Trusted** | Internal networks or devices handling non-sensitive general operations. | Workstations, B2B systems |
| **Restricted** | High-risk servers or databases requiring the strictest access controls. | Domain controllers, client databases |
| **Management** | Devices or services dedicated to managing the network or other infrastructure. | Virtualisation management, backup servers |
| **Audit** | Devices or services dedicated to security monitoring and telemetry. | SIEM, telemetry platforms |

---

### How Traffic is Controlled Between Zones

Most external traffic such as HTTP or mail stays within the **DMZ** and never reaches internal zones. However, when a remote user needs access to an internal resource, traffic rules can be created based on identifiers such as **MAC addresses** or **IP addresses** to define exactly what that user or device can reach. These rules are then enforced through **network security controls**.

Security zones and access controls physically direct where traffic can go, while **company security policy and compliance requirements** determine what access permissions are granted in the first place.

---

### Pathfinder Connection

Pathfinder's architecture already follows this zoning model. Student-facing upload endpoints sit in a **DMZ-equivalent** layer, Agent access is **Trusted**, Admin systems and the PostgreSQL database are **Restricted**, and the audit logging system maps directly to the **Audit zone** — meaning the security zone model was already built into Pathfinder by design.

---

### Questions

| Question | Answer |
|----------|--------|
| What zone would a user connecting to a public web server be in? | External |
| What zone would a public web server be in? | DMZ |
| What zone would a core domain controller be placed in? | Restricted |

---

## Task 4 — Traffic Filtering and ACLs

### Key Terminology

| Term | One-Line Definition |
|------|-------------------|
| **Traffic Filtering** | The process of controlling which network packets are allowed or dropped based on pre-defined rules. |
| **Policy** | A defined set of rules that determines how network traffic is handled before routing protocols take over. |
| **ACL (Access Control List)** | A standardised ruleset used to permit or deny network traffic based on criteria like source/destination address. |
| **ACE (Access Control Entry)** | A single rule within an ACL that defines a specific action (permit or deny) and the criteria to trigger it. |
| **QoS (Quality of Service)** | An IEEE standard (802.11e) that prioritises certain types of network traffic to ensure performance. |
| **Prefix List** | A list of IP address prefixes used as matching criteria in a routing or filtering policy. |
| **Permit** | An ACL action that allows matching traffic to pass through the router. |
| **Deny** | An ACL action that drops matching traffic and prevents it from being routed. |
| **Source Address** | The IP address where a packet originates — used as matching criteria in an ACE. |
| **Destination Address** | The IP address a packet is being sent to — used as matching criteria in an ACE. |
| **IEEE** | Institute of Electrical and Electronics Engineers — the body that standardises many networking protocols and policies. |

---

### Overview

Now that segmentation and secure architecture are in place, the next challenge is **enforcement** — how do we actually control what traffic can pass between VLANs? The answer is **traffic filtering using ACLs**, which allow a router to decide whether to route or drop a packet based on a defined list of rules before any other routing protocol is applied.

---

### What is an ACL?

An **ACL (Access Control List)** is a loose standard used across vendors to create rulesets for traffic filtering and access control. It is made up of individual **ACEs (Access Control Entries)**, each defining:

- An **action** — permit or deny
- A **criteria** — source address, destination address, or range

---

### ACL Structure in VyOS

```bash
# Step 1 — Create the ACL and assign it a number (1–2699)
set policy access-list <acl_number>

# Step 2 — Add a description
set policy access-list <acl_number> description <text>

# Step 3 — Create a rule (ACE) and define its action
set policy access-list <acl_number> rule <1-65535> action <permit|deny>

# Step 4 — Define the matching criteria (source or destination)
set policy access-list <acl_number> rule <1-65535> <destination|source> <any|host|inverse-mask|network>
```

---

### ACL in Action — Examples

#### ✅ Valid SSH Request — Permitted

```bash
# Packet: Source 10.10.212.209 → Destination Port 22 (SSH)
set policy access-list 1 rule 1 action permit
set policy access-list 1 rule 1 source 10.10.212.209
```
The source IP matches the ACE rule → packet is **accepted** and routed.

#### ❌ Invalid SSH Request — Denied

```bash
# Packet: Source 10.10.212.209 → Destination Port 2 (not SSH)
set policy access-list 1 rule 1 action deny
set policy access-list 1 rule 1 source 10.10.212.209
```
The source IP matches the ACE rule → packet is **dropped**.

---

### Limitation of ACLs on Routers

ACLs on a router provide **basic filtering** but are limited in extensibility — they cannot restrict traffic to a specific protocol or apply granular per-host protocol rules. This is why the next task introduces a **firewall**, which provides deeper inspection and more flexible rule enforcement.

---

### Pathfinder Connection

In Pathfinder, ACL-style logic is already applied at the API layer — FastAPI middleware checks the source role (Student, Agent, Admin) and permits or denies the request before it ever reaches the database. This is the software equivalent of a router ACL enforcing traffic rules at the network layer.

---

### Questions

| Question | Answer |
|----------|--------|
| Will the first packet result in a drop or accept? | **Accept** |
| Will the second packet result in a drop or accept? | **Drop** |

---

## Task 5 — Firewalls and Zone-Pairs

### Key Terminology

| Term | One-Line Definition |
|------|-------------------|
| **Firewall** | A network security device that monitors and controls incoming and outgoing traffic based on defined rules. |
| **Stateless Firewall** | A firewall that filters packets individually based on fixed criteria without tracking the state of a connection — like basic ACLs. |
| **Stateful Firewall** | A firewall that tracks the full state of a network connection and filters based on protocol, port, process, and direction. |
| **Traffic Correlation** | The process of analysing the state of a packet — its protocol, process, and direction — to make informed filtering decisions. |
| **Zone-Pair** | A directional, stateful firewall policy that enforces traffic rules between two specific zones in one direction at a time. |
| **Default Action** | The behaviour a firewall applies to any traffic that does not match a defined rule — typically set to drop for security. |
| **Ruleset** | A named collection of firewall rules applied to a zone-pair that defines what traffic is permitted or denied. |
| **State (established)** | A connection state where the initial handshake is complete and data is actively being exchanged. |
| **State (related)** | A connection state where a new connection is related to an already established one (e.g. FTP data channel). |
| **State (invalid)** | A packet that does not belong to any known connection state and should be dropped. |
| **IPv4-ICMP** | The Internet Control Message Protocol used for diagnostic commands like ping — filtered specifically in zone-pair rules. |
| **Sub-interface** | A virtual interface on a router tied to a specific VLAN, written as `<interface>.<VLAN number>` e.g. `eth0.10`. |

---

### Overview

ACLs provide basic filtering but lack the ability to inspect the **state** of a packet. A **stateful firewall** solves this by tracking the full context of a network connection, allowing much more precise enforcement of zone policies through **zone-pairs**.

---

### Stateless vs Stateful

| Type | Tracks State? | Example | Capability |
|------|--------------|---------|------------|
| **Stateless** | No | ACL | Filters by source/destination address only |
| **Stateful** | Yes | Zone-pair firewall | Filters by protocol, port, process, direction, and connection state |

---

### What is a Zone-Pair?

A zone-pair enforces rules for traffic flowing in **one specific direction** between two zones. Every pair of zones needs **two zone-pairs** — one for each direction.

```
DMZ → LAN  (one zone-pair)
LAN → DMZ  (separate zone-pair)
```

---

### Zone-Pair Table

| Zone A | Zone B | Protocol | Action |
|--------|--------|----------|--------|
| LAN | WAN | ICMP | Drop |
| WAN | LAN | ICMP | Accept |
| DMZ | LAN | HTTP | Accept |
| LAN | DMZ | ICMP | Accept |
| DMZ | WAN | — | Drop |
| WAN | DMZ | — | Drop |

---

### Step 1 — Configure Zone Policies

```bash
set zone-policy zone dmz default-action drop
set zone-policy zone dmz interface eth0.10

set zone-policy zone lan default-action drop
set zone-policy zone lan interface eth0.20

set zone-policy zone wan default-action drop
set zone-policy zone wan interface eth0.30
```

---

### Step 2 — Define Firewall Rulesets

#### LAN → WAN (Drop ICMP)

```bash
name lan-wan {
  default-action drop
  enable-default-log
  rule 1 {
    action accept
    state { established enable  related enable }
  }
  rule 2 {
    action drop
    log enable
    state { invalid enable }
  }
  rule 100 {
    action drop
    log enable
    protocol ipv4-icmp
  }
}
```

#### WAN → LAN (Accept ICMP)

```bash
name wan-lan {
  default-action drop
  enable-default-log
  rule 1 {
    action accept
    state { established enable  related enable }
  }
  rule 2 {
    action drop
    log enable
    state { invalid enable }
  }
  rule 100 {
    action accept
    log enable
    protocol ipv4-icmp
  }
}
```

---

### Step 3 — Apply Zone-Pairs to Zones

```bash
# Generic syntax
set zone-policy zone <zone A> from <zone B> firewall name <ruleset name>

# Example
set zone-policy zone LAN from WAN firewall name lan-wan
set zone-policy zone WAN from LAN firewall name wan-lan
```

---

### Static Site Exercise — Correct Configuration

| Common Name | Interface | Default Action |
|-------------|-----------|---------------|
| DMZ | eth0.10 | Drop |
| LAN | eth0.20 | Drop |
| WAN | eth0.30 | Drop |

| Source | Destination | Protocol | Action | Default Action |
|--------|-------------|----------|--------|---------------|
| DMZ | LAN | HTTP | Accept | Drop |
| DMZ | WAN | — | — | Drop |
| LAN | DMZ | ICMP | Accept | Drop |
| WAN | DMZ | — | — | Drop |

---

### Pathfinder Connection

Pathfinder should apply zone-pair logic at every service boundary — student upload requests (DMZ) should only be permitted to reach the FastAPI endpoint (LAN) over HTTPS/HTTP, and raw TCP connections from the DMZ must be dropped by default. The audit logging service should only receive traffic, never initiate it outward.

---

### Questions
![Task 5 - Correct Zone-Pair Configuration](https://raw.githubusercontent.com/Santyadhi87/Security-Engineer/1130d23f505f2f1777e7d99ed6968be4d78dcc8b/Assets/task5sna.png)

| Question | Answer |
|----------|--------|
| What is the flag found after filling in all blanks on the static site? | **THM{M05tly_53cure}** |

---

## Task 6 — SSL/TLS Inspection

### Key Terminology

| Term | One-Line Definition |
|------|-------------------|
| **SSL/TLS Inspection** | The process of intercepting, decrypting, and inspecting encrypted network traffic to detect hidden threats. |
| **SSL Proxy** | A middleman device that intercepts encrypted SSL/TLS traffic, decrypts it for inspection, then re-encrypts and forwards it. |
| **MitM (Man-in-the-Middle)** | A position in a network where a device sits between two communicating parties and can read or modify their traffic. |
| **UTM (Unified Threat Management)** | An all-in-one security platform that processes decrypted traffic through multiple services like web filters and IPS. |
| **IPS (Intrusion Prevention System)** | A security tool that monitors network traffic in real time and actively blocks detected threats. |
| **Web Filter** | A security service that blocks access to malicious or unauthorised websites based on URL or content categories. |
| **Deep SSL Inspection** | An advanced form of SSL inspection where decrypted traffic is fed into multiple UTM services for thorough analysis. |
| **Implant** | Malware planted on a compromised machine that communicates back to an attacker, often disguised as legitimate traffic. |
| **Beacon** | A regular, periodic signal sent by an implant back to an attacker's command and control server. |
| **Phishing** | A social engineering attack that tricks users into clicking malicious links or attachments to install malware. |
| **HTTPS** | Encrypted HTTP traffic using SSL/TLS — appears legitimate to firewalls, making it a common channel for hidden threats. |

---

### Overview

Even with proper zoning, VLANs, and zone-pair firewall rules in place, a threat actor can still hide malicious traffic inside **legitimate-looking HTTPS connections**. If an implant beacons home over HTTPS through the DMZ, the firewall sees it as normal encrypted web traffic and lets it through.

---

### The Problem — Encrypted Threats

```
LAN Machine (infected) → HTTPS beacon → DMZ → WAN → Attacker C2 server
                                ↑
                    Firewall sees: "looks like normal HTTPS"
                    Firewall does: nothing
```

---

### How SSL/TLS Inspection Works

```
Client → SSL Proxy (intercept + decrypt) → UTM Platform (inspect) → Re-encrypt → Destination
```

1. The **SSL proxy** intercepts the encrypted connection and acts as a MitM
2. Traffic is **decrypted** and passed to the **UTM platform**
3. UTM feeds decrypted traffic into services like **web filters** and **IPS**
4. If traffic is clean, it is **re-encrypted** and forwarded to its destination
5. If malicious, it is **blocked**

---

### Pros and Cons

| Pros | Cons |
|------|------|
| Detects threats hidden inside HTTPS | Requires a MitM proxy by design |
| Enables deep content inspection | Could intercept plain-text passwords mid-inspection |
| Feeds UTM services for full threat analysis | Advanced attackers can route through trusted cloud providers |
| Can block beacons and C2 traffic | Adds latency and complexity to the network |

---

### Pathfinder Connection

Pathfinder encrypts documents **at the application layer** with Fernet before they leave the client. Even if SSL inspection decrypts the HTTPS tunnel, the document contents remain encrypted and unreadable — a defence-in-depth approach.

---

### Questions

| Question | Answer |
|----------|--------|
| Does SSL inspection require a man-in-the-middle proxy? (Y/N) | **Y** |
| What platform processes data sent from an SSL proxy? | **UTM** |

---

## Task 7 — DHCP Snooping and Dynamic ARP Inspection

### Key Terminology

| Term | One-Line Definition |
|------|-------------------|
| **DHCP (Dynamic Host Configuration Protocol)** | A Layer 3 protocol that automatically assigns IP addresses to devices joining a network. |
| **DHCP Snooping** | A Layer 2 switch security feature that acts as a firewall between untrusted hosts and trusted DHCP servers. |
| **Rogue DHCP Server** | An unauthorised DHCP server on a network that hands out fake IP addresses to redirect or intercept traffic. |
| **DHCP Binding Database** | A table maintained by the switch that records the MAC address, IP address, VLAN, and interface of untrusted hosts. |
| **Trusted Host** | A device or interface that is permitted to send DHCP server responses without being filtered. |
| **Untrusted Host** | A device whose DHCP traffic is filtered and rate-limited by the switch until verified. |
| **ARP (Address Resolution Protocol)** | A protocol that maps an IP address to a MAC address so devices can communicate on a local network. |
| **Dynamic ARP Inspection (DAI)** | A security feature that validates ARP packets by comparing them against the DHCP binding database. |
| **ARP Spoofing** | An attack where a threat actor sends fake ARP messages to link their MAC address to a legitimate IP address. |
| **MAC Address** | A unique hardware identifier assigned to a network interface card, used at Layer 2 for device identification. |
| **Rate-Limiting** | Restricting how many packets a device can send per second to prevent flooding or abuse. |
| **DHCPRELEASE** | A DHCP message sent by a client to release its leased IP address back to the server. |
| **DHCPDECLINE** | A DHCP message sent by a client to decline an offered IP address, usually because it is already in use. |
| **Relay Agent** | A device that forwards DHCP messages between clients and servers across different subnets. |

---

### Overview

Even with VLANs, zone-pairs, and firewalls in place, attacks can still occur at **Layer 2** — specifically through rogue DHCP servers and ARP spoofing. DHCP Snooping and Dynamic ARP Inspection work together at the switch level to prevent these lower-level attacks before they escalate.

---

### DHCP Snooping

DHCP snooping sits on the **switch at Layer 2** and classifies every port as either **trusted** or **untrusted**. Untrusted host leases are stored in the **DHCP Binding Database**.

#### When DHCP Snooping Drops a Packet

| Condition | Reason |
|-----------|--------|
| DHCP packet received from outside the network | Could be a rogue server response |
| Source MAC and DHCP client hardware address do not match | Possible spoofing attempt |
| DHCPRELEASE or DHCPDECLINE on untrusted interface with unregistered source | Unauthorised release attempt |
| DHCP packet includes a relay agent address that is not `0.0.0.0` | Suspicious relay agent activity |

---

### Dynamic ARP Inspection (DAI)

ARP inspection validates **ARP packets** by comparing their MAC and IP address against the **DHCP Binding Database**. If the pair does not match, the packet is intercepted, logged, and discarded.

```
ARP Request arrives at switch
        ↓
DAI checks: Does Sender MAC + Sender IP match the DHCP Binding Database?
        ↓                          ↓
   Yes — forward             No — intercept, log, drop
```

---

### Valid vs Invalid ARP — Example

#### ✅ Valid ARP Request (Accepted)

```
Sender MAC: 02:c8:85:b5:5a:aa
Sender IP:  10.10.0.1

DHCP Binding Database:
02:c8:85:b5:5a:aa  →  10.10.0.1  ✅ Match — packet forwarded
```

#### ❌ Invalid ARP Request (Dropped — MAC Spoofed)

```
Sender MAC: 02:c8:85:bb:bb:bb  ← spoofed
Sender IP:  10.10.0.1

DHCP Binding Database:
02:c8:85:b5:5a:aa  →  10.10.0.1  ❌ Mismatch — packet dropped
```

---

### How DHCP Snooping and DAI Work Together

```
DHCP Snooping → builds DHCP Binding Database (MAC + IP + VLAN + Interface)
                          ↓
Dynamic ARP Inspection → uses that database to validate every ARP packet
```

---

### Pathfinder Connection

If Pathfinder were deployed on a physical corporate network, DHCP snooping and DAI would protect the switch layer from rogue devices trying to impersonate trusted servers or intercept traffic between students and the API gateway — exactly the kind of Layer 2 attack that bypasses higher-level firewalls entirely.

---

### Questions

| Question | Answer |
|----------|--------|
| Where does DHCP snooping store leased IP addresses from untrusted hosts? | **DHCP Binding Database** |
| Will a switch drop or accept a DHCPRELEASE packet? | **Drop** |
| Does dynamic ARP inspection use the DHCP binding database? (Y/N) | **Y** |
| Dynamic ARP inspection will match an IP address and what other packet detail? | **MAC Address** |

---

## Task 8 — Conclusion

### Summary

This room expanded the definition of a well-designed network to include **security as a core requirement** alongside redundancy and optimisation. Security must be designed and enforced at **every layer of the OSI model**.

| Task | Topic | OSI Layer |
|------|-------|-----------|
| Task 2 | VLANs and Segmentation | Layer 2 |
| Task 3 | Security Zones | Layer 2–3 |
| Task 4 | Traffic Filtering and ACLs | Layer 3 |
| Task 5 | Firewalls and Zone-Pairs | Layer 3–4 |
| Task 6 | SSL/TLS Inspection | Layer 4–7 |
| Task 7 | DHCP Snooping and ARP Inspection | Layer 2 |

### Key Takeaway

No single solution solves every network security problem. Each environment has different requirements, and security must be considered at every layer — from switch-level ARP inspection at Layer 2, all the way up to SSL/TLS inspection at Layer 7.

### Next Room
[Network Security Protocols](https://tryhackme.com/room/networksecurityprotocols) — exploring security from Layers 3 to 7.
