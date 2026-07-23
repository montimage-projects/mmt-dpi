# Development Guide

## Setting Up the Development Environment

### Prerequisites

- GCC 4.9 to 9.x (recommended: GCC 9)
- GNU Make
- `libxml2-dev`
- `libpcap-dev` (for examples and testing)
- Valgrind (for memory leak detection)

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install build-essential gcc make libxml2-dev libpcap-dev valgrind
```

> **Note:** Only Linux is currently supported. macOS and Windows are not supported.

## Building

### Standard Build

```bash
cd sdk
make -j$(nproc)
sudo make install
```

### Debug Build

```bash
cd sdk
make -j$(nproc) DEBUG=1
```

### Build with Logging

```bash
cd sdk
make -j$(nproc) SHOWLOG=1
```

### Build Options

| Option | Description | Source |
|--------|-------------|--------|
| `DEBUG=1` | Enable debug mode | `rules/common.mk:87` |
| `NDEBUG=1` | Define `-DNDEBUG` (default build; disables debug() output) | `rules/common.mk:38-42` |
| `SHOWLOG=1` | Show MMT_LOG messages (also defines `-DDEBUG -DHTTP_PARSER_STRICT`) | `rules/common.mk:160-162` |
| `VALGRIND=1` | Enable Valgrind compatibility | `rules/common.mk:95` |

<!-- FLAG: unverified — TCP_SEGMENT=1 and STATIC_LINK=1 were previously documented
     but no Makefile rule or code reference was found. -->

## Testing

### Run the Test Suite

```bash
cd sdk
make test
```

### Test with a Pcap File

```bash
cd src/examples
gcc -o extract_all extract_all.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
./extract_all -t /path/to/capture.pcap
```

### Memory Leak Detection

```bash
valgrind --leak-check=full --show-reachable=yes ./your_test_binary -t capture.pcap
```

## Debugging Tips

- Use `DEBUG=1` build flag for assertion checks and verbose output
- Use GDB with debug symbols: `gcc -g -o test test.c ...`
- Check protocol classification with `proto_attributes_iterator` example
- Use Wireshark to compare expected vs. actual protocol classification

## Code Organization

- Protocol implementations go in `src/mmt_tcpip/`, `src/mmt_mobile/`, etc.
- Each protocol has a `proto_<name>.c` file
- Public headers are in `src/mmt_core/public_include/`
- Build rules are in `rules/`

## Creating Packages

### Debian Package

```bash
cd sdk
make deb
```

(`sdk/Makefile:119`)


