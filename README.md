# Galaxy-Tunnel-Tech/GT-V2.0 

A Serverless VLESS proxy with Advanced Features, initially built for Cloudflare Workers.

## Overview
This repository contains the logic for a VLESS proxy proxy including:
- **Proxy Logic:** VLESS handshake validation and destination extraction.
- **Outbound Connection:** Uses Cloudflare sockets to pipe data via TCP.
- **Routing:** Built-in proxy pool for IP balancing, custom rules (`ROUTE_RULES`), ad-blocking, and SSRF protection.
- **DoH (DNS-over-HTTPS):** Ensures secure DNS resolution.
