# xdp-knock

XDP-based port knocking for Linux.

xdp-knock dynamically opens ports for authorized users while remaining invisible to unauthorized traffic, including port scanners and crawlers.

## How it works

```
Unauthorized IP  →  XDP_DROP
Valid knock packet     →  ringbuf → userspace HMAC check → added to allowed_map
Authorized IP    →  XDP_PASS (until access window expires)
```

1. **Default deny**: traffic from unknown IPs is dropped by the XDP program.
2. **Knock Packet**: client sends a UDP packet to `knock_port`(configured in config) with a 40-byte payload:
   - 8-byte big-endian Unix timestamp
   - 32-byte HMAC-SHA256(`shared_secret`, timestamp)
3. **Verify**: BPF copies the payload to a ring buffer; userspace validates the HMAC and checks the timestamp.
4. **Allow**: on success, the source IP is stored in `allowed_map` for `access_window_s` seconds.
5. **Authorized**: subsequent packets from that IP skip knock handling and return `XDP_PASS`.

## Requirements

- Linux with XDP support
- `clang`, `llvm`, `bpftool`, `libbpf-dev`, `libelf-dev`, `libssl-dev`
- Kernel BTF headers (`vmlinux.h`) - regenerate before building if the placeholder header is empty

## Build

```bash
make
```

This compiles the BPF object, generates `include/xdp-knock.skel.h`, and links the userspace binary.

## Configuration

Edit `config.cfg`:

| Option | Description |
|--------|-------------|
| `interface` | Network interface to attach the XDP program |
| `knock_port` | UDP port that accepts knock packets |
| `shared_secret` | Secret used for HMAC-SHA256 |
| `access_window_s` | How long (seconds) an authorized IP stays allowed |

## Run

```bash
sudo ./xdp-knock
```

The program reads `config.cfg`, attaches to the configured interface, and polls the ring buffer for knock packets.

## Authorize a client

Use `authorize.py` (Scapy) or any client that sends the same payload format:

```bash
pip install scapy
sudo python3 authorize.py
```

**Payload layout (40 bytes):**

```
[timestamp: 8 bytes BE][HMAC-SHA256: 32 bytes]
```

**UDP knock packet requirements:**

- Destination port = `knock_port`
- UDP length = 48 (8-byte header + 40-byte payload)
