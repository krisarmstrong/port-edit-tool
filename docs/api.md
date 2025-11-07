# API Documentation

## Main Application

**Executable**: `voip_port_edit.exe` / `voip_port_edit`

PCAP file port number editor for VoIP traffic.

### Usage

```bash
./voip_port_edit <input.pcap> <output.pcap> <old_port> <new_port>
```

**Arguments**:
- `input.pcap`: Input PCAP file path
- `output.pcap`: Output PCAP file path
- `old_port`: Port number to find
- `new_port`: New port number to set

**Example**:
```bash
./voip_port_edit capture.pcap modified.pcap 5060 5061
```

## Compilation

### Windows (Visual Studio)
```bash
cl /EHsc voip_port_edit.cpp
```

### Linux/Mac (GCC)
```bash
g++ -o voip_port_edit src/voip_port_edit.cpp
```

### Dependencies

- Standard C++ library
- PCAP file format knowledge
- Network byte order functions

## Supported Features

### Port Types
- UDP source ports
- UDP destination ports
- TCP source ports (if applicable)
- TCP destination ports (if applicable)

### PCAP Format
- Standard libpcap format
- Ethernet frames
- IP packets (IPv4)
- UDP/TCP segments

## Technical Details

### Checksum Recalculation

The tool must recalculate:
- IP header checksum
- UDP/TCP checksum
- Maintains packet validity

### Byte Order

Handles network byte order (big-endian):
- Port numbers (16-bit)
- IP addresses (32-bit)
- Length fields

## Return Codes

- `0`: Success
- `1`: File open error
- `2`: Invalid PCAP format
- `3`: Invalid port number
- `4`: Write error

## Limitations

- IPv4 only (no IPv6 support)
- UDP/TCP only
- Single port replacement per run
- No regex or wildcard matching

---
Author: Kris Armstrong
