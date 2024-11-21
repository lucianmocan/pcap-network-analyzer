# pcap-network-analyzer

## 1. Overview

The project is a network analyzer designed with modularity and extensibility in mind.

It provides:

- an **API** as the core component for analyzing pcap files and network traffic, enabling both current and future integrations
- a **CLI** interface for immediate interaction and usability
- a **GUI** planned for future development

Protocols supported: 

- [ ] Ethernet  

- [ ] IPv4  

- [ ] IPv6  

- [ ] UDP  

- [ ] TCP  

- [ ] ICMP  

- [ ] ARP  

- [ ] ICMPv6  

- [ ] BOOTP  

- [ ] DHCP  

- [ ] DNS  

- [ ] HTTP  

- [ ] FTP  

- [ ] SMTP  

- [ ] IMAP  

- [ ] POP3  

- [ ] TELNET 



## 2. Goals and Scope

#### Short term goals:

- develop the core with support for protocol parsing
- expose an API
- develop the CLI app

#### Long term goals:

- extend the API for GUI or web integration
- add statistics
- develop a GUI



## 3. Architecture Overview

I want an architecture that follows, to a certain degree, the principle of hexagonal architecture.

The idea is to be able to develop each component independently, to facilitate writing tests and ease future development.

#### 3.1 Layered Components

1. Core

   - handles protocol parsing and packet analysis
   - modular design to simplify adding new protocols

2. API

   - expose functions to interfaces (CLI, GUI)
   - abstract the core's complexity

3. CLI

   - initial interface for interacting with the tool
   - user input, API calls, output results

4. GUI (Future)

   - visual interface for a more modern look
   - based entirely on the API


