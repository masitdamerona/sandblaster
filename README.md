# SandBlaster: Reversing the Apple Sandbox

## Cellebrite Fork

This fork was updated to work on iOS 18 and iOS 26.

Authored by Yarden Hamami of Cellebrite Labs.

## Description

SandBlaster is a tool for reversing (decompiling) binary Apple sandbox profiles. Apple sandbox profiles are written in SBPL (*Sandbox Profile Language*), a Scheme-like language, and are then compiled into an undocumented binary format and shipped. Primarily used on iOS, sandbox profiles are present on macOS as well.

The technical report [SandBlaster: Reversing the Apple Sandbox](https://arxiv.org/abs/1608.04303) presents extensive information on SandBlaster internals.

SandBlaster relied on previous work by [Dionysus Blazakis](https://github.com/dionthegod/XNUSandbox) and Stefan Esser's [code](https://github.com/sektioneins/sandbox_toolkit) and [slides](https://www.slideshare.net/i0n1c/ruxcon-2014-stefan-esser-ios8-containers-sandboxes-and-entitlements).

---

## Supported iOS Versions and Branches

| Branch | Supported Versions |
|--------|--------------------|
| `master` | iOS 16.5, iOS 17.x |
| `iOS18Plus` | iOS 18.x, iOS 26.x |

> Select the branch that matches your target iOS version.

---

## Installation

### Dependencies

```bash
# Python package
pip install unicorn

# ipsw CLI (kernel cache download and analysis)
brew install blacktop/tap/ipsw
```

- **unicorn**: ARM64 emulator. Used to emulate kext code and locate sandbox profile binaries in memory.
- **ipsw**: Used to download kernel caches, extract kexts, and disassemble binaries.

---

## Method 1: Automated Extraction (Recommended)

`helpers/extract_sb.py` automates the entire pipeline in a single command.

### How It Works

```
1. Download the kernel cache for the specified device and version via ipsw
2. Extract the com.apple.security.sandbox kext from the kernel cache
3. Disassemble the kext and locate the profile-loading code for each profile
4. Emulate the loading code with Unicorn to resolve each profile's address and size
5. Dump the profile binary using ipsw macho dump (saved as .bin)
6. Invoke reverse_sandbox.py to decompile the binary
7. Write the output file (.sb by default, or .c / Mach-O depending on options)
```

Profiles extracted:
- `builtin collection`
- `autobox collection` (iOS 18+) / `protobox collection` (iOS 17 and below)
- `platform collection`

### Usage

```bash
# Default — produce SBPL (.sb) files
python3 helpers/extract_sb.py --device iPhone16,1 --version 17.6.1

# Generate C output
python3 helpers/extract_sb.py --device iPhone16,1 --version 17.6.1 --c-output

# Generate Mach-O binary (implies --c-output)
python3 helpers/extract_sb.py --device iPhone16,1 --version 17.6.1 --macho

# Skip decompilation — extract binaries only
python3 helpers/extract_sb.py --device iPhone16,1 --version 17.6.1 --skip-decompile
```

### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--device` | `-d` | `iPhone16,1` | Device identifier |
| `--version` | `-v` | `17.6.1` | iOS version |
| `--skip-decompile` | `-s` | `False` | Skip decompilation, extract binaries only |
| `--c-output` | `-c` | `False` | Generate `.c` file instead of `.sb` |
| `--macho` | `-m` | `False` | Compile `.c` into a Mach-O binary (implies `-c`) |

### Version Specification

> **Always specify the exact version including the minor version.**

```bash
# Correct
--version 17.6.1
--version 18.0 beta 4

# Not recommended
--version 17        # Downloads all builds (beta, RC, release) for major version
--version 17.6      # Downloads all builds for that minor version
```

Additional notes:
- The device identifier must contain `iPhone` (e.g. `iPhone16,1`, `iPhone14,2`).
- If the kernel cache already exists locally, path parsing may fail. Use Method 2 in that case.

---

## Method 2: Manual Extraction

Use this method when you already have the binary profile and operations file, or when automated extraction fails.

### How It Works

```
1. Parse the binary sandbox profile header to extract layout offsets
2. Build the operation node graph for each operation
3. Reduce the graph and convert it to SBPL text (or C)
4. Write the output file(s)
```

### Important

`reverse_sandbox.py` **must be run from within the `reverse-sandbox/` directory**. It references sibling Python modules (`operation_node.py`, `sandbox_filter.py`, etc.) and `logger.config` using relative paths.

```bash
cd reverse-sandbox/

# SBPL output
python3 reverse_sandbox.py \
    --release 17 \
    --operations_file /path/to/operations.txt \
    --directory /path/to/output/ \
    /path/to/profile.bin

# C file output
python3 reverse_sandbox.py \
    --release 17 \
    -c \
    --operations_file /path/to/operations.txt \
    --directory /path/to/output/ \
    /path/to/profile.bin

# Mach-O binary (requires clang)
python3 reverse_sandbox.py \
    --release 17 \
    -c -m \
    --operations_file /path/to/operations.txt \
    --directory /path/to/output/ \
    /path/to/profile.bin

# Reverse specific operations only
python3 reverse_sandbox.py \
    --release 17 \
    --operations_file /path/to/operations.txt \
    --directory /path/to/output/ \
    -n network-inbound network-outbound \
    /path/to/profile.bin

# Reverse a specific profile from a bundle
python3 reverse_sandbox.py \
    --release 17 \
    --operations_file /path/to/operations.txt \
    --directory /path/to/output/ \
    -p container \
    /path/to/sandbox_bundle.bin
```

### Options

| Option | Short | Required | Description |
|--------|-------|----------|-------------|
| `filename` | — | Yes | Path to the binary sandbox profile |
| `--release` | `-r` | Yes | iOS major version (e.g. `17`, `18`) |
| `--operations_file` | `-o` | Yes | File containing the list of sandbox operations |
| `--directory` | `-d` | No | Output directory (default: current directory) |
| `--profile` | `-p` | No | Profile name to reverse (for bundles) |
| `--operation` | `-n` | No | Specific operation(s) to reverse |
| `--print_sandbox_profiles` | `-psb` | No | Print profile list from a bundle (iOS 9+) |
| `--keep_builtin_filters` | `-kbf` | No | Keep builtin filters in the output |
| `--c_output` | `-c` | No | Generate `.c` file instead of `.sb` |
| `--macho` | `-m` | No | Compile `.c` into a Mach-O binary (implies `-c`) |

---

## Output

### SBPL Mode (Default)

A directory is created for each profile containing the raw binary and the decompiled `.sb` file.

```
<kext_directory>/
├── operations.txt
├── builtin_collection/
│   ├── builtin_collection.bin
│   └── builtin_collection.sb
├── autobox_collection/
│   ├── autobox_collection.bin
│   └── autobox_collection.sb
└── platform_collection/
    ├── platform_collection.bin
    └── platform_collection.sb
```

Example `.sb` content:

```scheme
(version 1)
(deny default)
(allow file-read-metadata
    (literal "/"))
(allow network-outbound
    (remote tcp))
```

### C Mode (`-c`)

A `.c` file is produced instead of `.sb`. Each sandbox operation is represented as a C function. Operation names containing `*` are replaced with `$`, and `-` with `_`.

```c
extern long allow(const char *);
extern long deny(const char *);
...

long file_read_metadata()
{
    if (literal("/")) return allow("");
    ...
}
```

### Mach-O Mode (`-m`)

The `.c` file is compiled with `clang -O0` into a Mach-O binary alongside the `.c` file. The binary can be loaded into a decompiler such as Hex-Rays for further analysis.

Example Hex-Rays output:

```c
long dynamic_code_generation()
{
  if ( !entitlement_is_bool_true("dynamic-codesigning") )
    return deny("message 'MAP_JIT requires the dynamic-codesigning entitlement'");
  if ( !process_attribute("is-sandboxed") || process_attribute("is-protoboxed") )
    return deny("message 'MAP_JIT requires sandboxing'");
  return allow("");
}
```

### Metadata File (Bundle Profiles)

When processing a bundle (`type == 0x8000`), a `.metadata` file is written alongside each profile output:

```
base_profile: <parent profile name>

states_flag: 0x...

policies:
    [...]

states:
    [...]
```

### Logging

- **Console**: `INFO` level and above
- **File**: `reverse-sandbox/reverse.log` — `DEBUG` level and above

---

## Project Structure

```
sandblaster/
├── helpers/
│   └── extract_sb.py          # Automated helper: download → extract → decompile
└── reverse-sandbox/
    ├── reverse_sandbox.py     # Main script: CLI parsing, binary parsing, orchestration
    ├── operation_node.py      # Core: operation node graph construction and SBPL conversion
    ├── sandbox_filter.py      # Filter (match rule) handling
    ├── filters.py             # Filter definitions
    ├── filters.json           # Filter configuration
    ├── sandbox_regex.py       # Regex automaton to string conversion
    ├── regex_parser.py        # Binary regex parsing
    ├── reverse_string.py      # iOS 10+ string format handling
    ├── modifiers.py           # Modifier definitions
    ├── modifiers.json         # Modifier configuration
    └── logger.config          # Logging configuration
```

---

## License

BSD 3-Clause License. Copyright (c) 2016, North Carolina State University and University POLITEHNICA of Bucharest.
