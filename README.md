# Toy VPN example

This is very basic PoC of VPN service via socks5.

Client uses TUN to catch IPv4 packages, performs mock socks5 handshake with server and makes requests via server.

Lacks proper error handling, tests, supports only TCP (and probably does it wrong, I'm sure under load seq and ack numbers will float), and, of course, no encryption.

Basically just wanted to play with the pipeline, see how it works, learn the protocol.

And yeah, not really a proper NAT yet.

## Run example

```bash
docker compose up --build
docker exec -it $(docker ps -qf "ancestor=vpn_nat-client") /bin/bash
curl -v http://44.205.165.147:80/headers
```

## Update 1 (1.11.2025)

Added AEAD level (Shadowsocks style): now TCP payload between client and server is encrypted.

Planned TODOs:
* properly split IPv4 logic in client to make it testable (separate reading bytes from TUN device and parsing them as IPv4/TCP):

	* do something about blocking reads/writes on TUN device, create async wrap for it;
* think about key exchange protocol for AEAD;
* ShadowTLS: add TLS between client and server;
