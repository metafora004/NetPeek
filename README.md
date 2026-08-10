# NetPeek 0.2.0

NetPeek is a cross-platform network discovery and local port inspection tool
written in C++20 with Qt 6 Widgets.

## Network Scanner

- Detects active local IPv4 interfaces and calculates their CIDR subnets.
- Accepts a single IPv4 address, CIDR, short range, or full IPv4 range.
- Discovers devices with ICMP and an independent TCP fallback.
- Displays every checked address with `Scanning`, `Online`, or `No response` status.
- Resolves host names and measures response time.
- Scans up to 1024 selected TCP ports with bounded concurrency.
- Shows common service names next to open ports.
- Supports numeric IP sorting, result filtering, and context-menu copying.
- Persists the last target, ports, timeout, and window geometry with `QSettings`.

The TCP fallback treats both a successful connection and a rejected connection
as proof that the target is reachable. This lets NetPeek discover hosts that
block ICMP without relying on raw sockets or administrator privileges.

## PortWatch

- Shows locally bound/listening TCP and UDP ports.
- Displays protocol, local address, port, PID, and process name.
- Uses `/proc` on Linux, IP Helper API on Windows, and `lsof` on macOS.
- Supports sorting and manual refresh.

Process ownership information can be limited by operating-system permissions.

## Build

Requirements: CMake 3.21+, a C++20 compiler, and Qt 6.5+ with Core, Network,
and Widgets.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Windows example:

```powershell
cmake -S . -B build -DCMAKE_PREFIX_PATH=C:/Qt/6.5.3/msvc2019_64
cmake --build build --config Release
```

## Accepted targets

- `192.168.1.42`
- `192.168.1.0/24`
- `192.168.1.10-80`
- `192.168.1.10-192.168.1.80`

One scan is limited to 4096 IPv4 addresses and 1024 TCP ports. Large scans
require confirmation in the interface.

Only scan systems and networks you own or are explicitly authorized to test.

## Architecture

- `Ipv4Range` validates targets and produces bounded address lists.
- `NetworkInterfaces` enumerates active interfaces and derives IPv4 subnets.
- `HostDiscovery` runs a bounded asynchronous ICMP discovery queue.
- `NetworkScanner` performs asynchronous TCP checks and supplies TCP fallback.
- `LocalPortsProvider` implements platform-specific PortWatch backends.
- `MainWindow` merges discovery and port results into the Qt Widgets interface.

## Roadmap

- IPv6 network scanning and Windows IPv6 PortWatch.
- Scan profiles and custom service dictionaries.
- CSV/JSON export and scan history.
- MAC/vendor discovery for local networks.
