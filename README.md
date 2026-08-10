# NetPeek

NetPeek is a cross-platform network inspection utility built with C++20 and Qt 6.

Current MVP features:

- Scan a single IPv4 address, a CIDR subnet, or an IPv4 range.
- Check a configurable list of TCP ports concurrently.
- Resolve host names for discovered nodes.
- Show locally bound/listening TCP and UDP ports with PID and process name.
- Native local-port collection on Linux and Windows; `lsof` integration on macOS.

## Build

Requirements: CMake 3.21+, a C++20 compiler, and Qt 6.5+ with the Core, Network,
and Widgets modules.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

On Windows, open a terminal configured for your Qt kit, or pass
`-DCMAKE_PREFIX_PATH=C:/Qt/6.x.x/msvc2022_64` to CMake.

## Scan input

Accepted targets:

- `192.168.1.42`
- `192.168.1.0/24`
- `192.168.1.10-80`
- `192.168.1.10-192.168.1.80`

For safety, one scan is limited to 4096 addresses and 1024 ports. Only hosts
with at least one open selected TCP port are listed in this MVP.

PortWatch may need elevated privileges to associate sockets owned by other
users with their processes on Linux and Windows.

Only scan systems and networks you own or are explicitly authorized to test.

## Project structure

- `src/network` — IPv4 target parsing and asynchronous TCP scanning.
- `src/ports` — platform-specific local socket/process discovery.
- `src/MainWindow.*` — Qt Widgets interface and presentation logic.

## Roadmap

- ICMP/ARP host discovery and IPv6 network scanning.
- Service identification and configurable scan profiles.
- CSV/JSON export, filtering, and scan history.
- Signed platform packages and automated CI builds.

