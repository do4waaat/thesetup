# thesetup

A modular C++ framework for learning Windows internals and Red Team development techniques.

## Current Features

### Core Components
- **PE Parser**: Manual parsing of PE headers, sections, and import tables
- **PEB Walker**: Dynamic API resolution without `GetProcAddress`
- **Indirect Syscalls**: Bypass user-mode hooks via direct syscall invocation (Hell's Gate SSN resolution)

### Evasion
- **AMSI Bypass**: Hardware breakpoint-based bypass for Anti-Malware Scan Interface
- **Manual Mapping**: Load DLLs without `LoadLibrary`, resolving imports and applying relocations

### Utilities
- **RAII Wrappers**: Safe resource management for Windows API handles and memory

## Roadmap

- [ ] ETW patching (Event Tracing for Windows)
- [ ] Anti-debug techniques
- [ ] Anti-VM detection
- [ ] Module stomping integration
- [ ] Process hollowing
- [ ] Call stack spoofing
- [ ] Sleep obfuscation
- [ ] Persistence mechanisms

## Build

```bash
cmake -B build
cmake --build build
