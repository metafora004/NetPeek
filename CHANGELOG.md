# Changelog

## 0.2.0 — 2026-08-10

### Added

- Automatic discovery of active local IPv4 interfaces and CIDR subnets.
- Bounded asynchronous ICMP discovery with TCP reachability fallback.
- `Scanning`, `Online`, and `No response` host states.
- Response time and discovery method columns.
- Display of every checked address, including hosts without open selected ports.
- Common service names for open TCP ports.
- Numeric IP sorting and result filtering.
- Context-menu copying of IP address, host name, and ports.
- Persistent scanner settings and window geometry.

### Changed

- Network and discovery progress are combined into one progress indicator.
- The scanner table now merges ICMP, DNS, and TCP results per host.
- PortWatch tables can be sorted by column.

## 0.1.0 — 2026-08-10

- Initial IPv4 TCP scanner and cross-platform local PortWatch MVP.
