# Architecture

## Overview

VoIP Port Edit Tool is a C++ application for editing port numbers in VoIP PCAP files. It modifies RTP/UDP port values in captured network traffic for testing and analysis purposes.

## System Architecture

### Core Components

1. **Main Application** (`voip_port_edit.cpp`)
   - PCAP file parsing
   - Packet header manipulation
   - Port number modification
   - File output generation

### Technical Implementation

#### PCAP File Processing

Uses libpcap or custom parsing:
- Binary file reading
- Packet header parsing
- Ethernet/IP/UDP layer access
- Checksum recalculation

#### Port Modification Algorithm

Multi-layer packet editing:
1. Read PCAP file structure
2. Locate UDP/TCP headers
3. Modify source/destination ports
4. Recalculate checksums
5. Write modified packets

### Data Flow

```
Input PCAP → Packet Parser → Header Locator → Port Editor → Checksum Update → Output PCAP
```

### Header Manipulation

Handles multiple protocol layers:
- Ethernet headers (Layer 2)
- IP headers (Layer 3)
- UDP/TCP headers (Layer 4)
- Payload preservation

## Design Principles

1. **Accuracy**: Maintain packet integrity
2. **Performance**: Efficient file processing
3. **Compatibility**: Standard PCAP format
4. **Reliability**: Proper checksum handling

---
Author: Kris Armstrong
