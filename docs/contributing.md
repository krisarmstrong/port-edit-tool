# Contributing to VoIP Port Edit Tool

## Welcome

Thank you for your interest in contributing to VoIP Port Edit Tool!

## Getting Started

### Prerequisites

- C++ compiler (GCC, Clang, or MSVC)
- Make or CMake (optional)
- Git
- Basic understanding of network protocols

### Setup

1. Clone the repository
2. Compile the source:
   ```bash
   g++ -o voip_port_edit src/voip_port_edit.cpp
   ```

## Development Workflow

### Making Changes

1. Create a new branch for your feature or fix
2. Make your changes in the `src/` or `include/` directory
3. Test with various PCAP files
4. Update documentation as needed
5. Commit with clear, descriptive messages

### Code Standards

- Follow C++ best practices
- Use meaningful variable names
- Add comments for complex logic
- Handle errors gracefully
- Maintain cross-platform compatibility

### Testing

Test with sample PCAP files:
```bash
./voip_port_edit tests/sample.pcap output.pcap 5060 5061
```

Verify output with Wireshark:
- Open modified PCAP in Wireshark
- Check port numbers changed correctly
- Verify checksums are valid
- Ensure no packet corruption

## Performance Considerations

- Optimize for large PCAP files
- Minimize memory usage
- Consider streaming approach
- Profile for bottlenecks

## Pull Request Process

1. Ensure code compiles on multiple platforms
2. Test with various PCAP files
3. Update documentation
4. Add usage examples
5. Submit PR with clear description

## Questions?

Feel free to open an issue for questions or discussions.

---
Author: Kris Armstrong
