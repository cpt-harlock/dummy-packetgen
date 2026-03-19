# packetgenlatency

A DPDK application that simultaneously transmits dummy UDP packets and receives incoming packets.

## Prerequisites

- DPDK installed (libraries + headers) and discoverable via `pkg-config` (`pkg-config --modversion libdpdk`)
- Meson & Ninja build system
- Hugepages configured (`echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`)
- At least one NIC bound to a DPDK-compatible driver (e.g. `vfio-pci`)

## Build

```bash
meson setup build
ninja -C build
```

## Run

The app needs at least **2 lcores** (one for TX on main, one for RX on a worker):

```bash
sudo ./build/packetgenlatency -l 0-1 -n 4 -- --payload-len 64 --range
```

Common EAL options:

| Flag | Description |
|------|-------------|
| `-l 0-1` | Lcores to use (min 2 recommended) |
| `-n 4` | Memory channels |
| `-a 0000:03:00.0` | Whitelist a specific PCI device |
| `--vdev=net_pcap0,iface=eth0` | Use a pcap virtual device for testing |

### Testing without real hardware

```bash
sudo ./build/packetgenlatency -l 0-1 -n 4 \
    --vdev=net_pcap0,iface=eth0 --no-pci --
```

Press **Ctrl-C** to stop; the app prints TX/RX totals on exit.

### App options

| Flag | Description |
|------|-------------|
| `--pps N` | Target TX rate in packets per second (`0` = line rate) |
| `--tx-cores N` | Number of TX lcores (includes main lcore). Default `1` |
| `--payload-len N` | UDP payload size in bytes (default `64`) |
| `--range` | Change the last 2 bytes of the destination IPv4 address for each packet |
| `--debug` | Hex-dump received packets and parsed timestamp fields |

### `--tx-cores` examples

Default behavior (single TX lcore on main):

```bash
sudo ./build/packetgenlatency -l 0-3 -n 4 -- --tx-cores 1 --range
```

Two TX lcores (main + one worker), remaining workers used for RX:

```bash
sudo ./build/packetgenlatency -l 0-5 -n 4 -- --tx-cores 2 --test --range
```

Four TX lcores (main + three workers) with a global rate limit:

```bash
sudo ./build/packetgenlatency -l 0-9 -n 4 -- --tx-cores 4 --pps 4000000 --range
```

Note: `--tx-cores` must be less than or equal to the total selected lcores, and the NIC must support at least that many TX queues.

## Dummy packet format

| Layer | Details |
|-------|---------|
| Ethernet | Src `00:AA:BB:CC:DD:EE` → Dst `00:11:22:33:44:55`, EtherType IPv4 |
| IPv4 | `10.0.0.1` → `10.0.0.2`, TTL 64; with `--range`, the last 2 bytes of the destination IP increment per packet |
| UDP | Src port `12345` → Dst port `54321` |
| Payload | Configurable length (default 64 bytes), incrementing pattern |

Edit the `#define` constants at the top of `main.c` to customise addresses or ports.
