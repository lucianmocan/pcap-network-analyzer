# pcap-network-analyzer

## 1. Overview

The project is a network analyzer designed with modularity and extensibility in mind.

It provides:

- an **API** as the core component for analyzing pcap files and network traffic, enabling both current and future integrations
- a **CLI** interface for immediate interaction and usability
- a **GUI** planned for future development

| **Protocol** | **Parser**         | **CLI**           | **Test Coverage** |
|--------------|--------------------|-------------------|-------------------|
| Ethernet     | <ul><li>[x]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[x]&nbsp;</li></ul> |
| IPv4         | <ul><li>[x]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| IPv6         | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| UDP          | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| TCP          | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| ICMP         | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| ARP          | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| ICMPv6       | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| BOOTP        | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| DHCP         | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| DNS          | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| HTTP         | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| FTP          | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| SMTP         | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| IMAP         | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| POP3         | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |
| TELNET       | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> | <ul><li>[ ]&nbsp;</li></ul> |



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

![Architecture Chart](https://i.imgur.com/mIDBUcJ.jpeg)

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


