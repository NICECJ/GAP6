# GAP6

GAP6 is an IPv6 active address discovery framework. The project contains two main parts:

1. `RFC-codegen`: analyzes RFC documents and extracts IPv6 probing mechanisms.
2. `New-address-discovery`: converts probing mechanisms into protocol plugins and runs IPv6 active probing.

The typical workflow is:

```text
RFC documents
    -> RFC-codegen
    -> structured probing mechanism reports
    -> New-address-discovery
    -> C protocol plugins
    -> IPv6 probing results
```

> Use this project only on networks and address spaces that you are authorized to test.

---

## Requirements

### Common requirements

- Linux environment
- Python 3.9 or later
- Internet access if RFC downloading or LLM-based code generation is required

### Python packages

Install the Python dependencies manually:

```bash
python3 -m pip install openai requests tiktoken
```

### C probing runtime requirements

The address discovery component uses raw sockets, so it should be built and run on Linux with root privileges.

Required tools:

```bash
sudo apt update
sudo apt install build-essential make gcc
```

---

## Repository Structure

```text
GAP6-main/
|-- RFC-codegen/
|   |-- RFC/                 # RFC text/XML files
|   |-- ipv6_probes/         # Generated IPv6 probing mechanism reports
|   |-- main.py              # Main RFC analysis entry point
|   |-- config.py            # LLM and RFC processing configuration
|   |-- pipeline.py          # End-to-end RFC processing pipeline
|   |-- analyzer.py          # Chunk-level probing candidate extraction
|   |-- aggregator.py        # RFC-level mechanism aggregation
|   |-- classifier.py        # Logical deduplication of extracted mechanisms
|   |-- rfc_parser.py        # RFC XML parser
|   |-- cleaner.py           # RFC text cleaner
|   |-- splitter.py          # RFC section/chunk splitter
|   |-- metadata_filter.py   # RFC metadata filtering
|   `-- downloader.py        # RFC downloader
|
`-- New-address-discovery/
    |-- input/               # IPv6 prefixes or exact IPv6 address lists
    |-- ipv6_probes/         # RFC probing mechanism reports used for plugin generation
    |-- protocols/           # Protocol plugin implementations
    |-- include/             # Header files for the probing framework
    |-- src/                 # Core C probing framework
    |-- Makefile             # Build script
    |-- run.sh               # Run one protocol plugin
    |-- run_all_protocols.sh # Run all protocol plugins
    |-- llm_protocol_builder.py
    |-- generate_plugins.py
    `-- count_unique_ipv6.py
```

---

# 1. RFC-codegen

`RFC-codegen` is responsible for reading RFC documents and extracting protocol behaviors that may be useful for active IPv6 address probing.

It performs the following steps:

1. Downloads RFC documents into `RFC/`.
2. Parses XML or plain-text RFC files.
3. Cleans and splits long RFC documents into smaller chunks.
4. Uses an LLM to extract candidate IPv6 probing behaviors.
5. Aggregates chunk-level candidates into RFC-level mechanisms.
6. Deduplicates similar mechanisms.
7. Writes structured probing reports into `ipv6_probes/`.

## Important Files

### `config.py`

This file controls the RFC analysis process.

Important options include:

```python
BASE_URL = "https://api.siliconflow.cn/v1"
API_KEY = "your_api_key"
MODEL = "deepseek-ai/DeepSeek-V3"

RFC_FOLDER = "RFC"
OUTPUT_DIR = "./ipv6_probes"

MAX_FILES_TO_PROCESS = 500
MAX_TOKENS = 6000

DOWNLOAD_START_RFC = 6000
DOWNLOAD_END_RFC = 6010

SKIP_ALREADY_ANALYZED_RFC = True
RETRY_FAILED_RFC = False
```

Before running, replace `API_KEY` with your own key. Do not commit real API keys to a public repository.

### `main.py`

This is the main entry point. It downloads RFC files, filters them, processes them through the pipeline, and records progress in `process_log.json`.

### `pipeline.py`

This file defines the full RFC processing workflow:

```text
load RFC
  -> clean/parse
  -> split into chunks
  -> extract candidate mechanisms
  -> aggregate mechanisms
  -> classify and deduplicate
  -> write output report
```

### `ipv6_probes/`

This folder stores the extracted probing mechanism reports. Each useful RFC produces one report:

```text
ipv6_probes/rfcXXXX.txt
```

A report usually contains:

- mechanism name
- protocol information
- packet template
- fields to modify
- packet flow
- receive filter
- success and failure conditions
- RFC reference information

These reports are later used by `New-address-discovery` to generate C protocol plugins.

## How to Run RFC-codegen

From the repository root:

```bash
cd RFC-codegen
python3 -m pip install openai requests tiktoken
python3 main.py
```

After the program finishes, check the output directory:

```bash
ls ipv6_probes/
```

Example output files:

```text
rfc4291.txt
rfc4294.txt
rfc4861.txt
```

## Resume Behavior

`process_log.json` records the processing status of each RFC file. If `SKIP_ALREADY_ANALYZED_RFC` is set to `True`, RFC files that were already processed successfully will be skipped in the next run.

To force reprocessing, either:

1. set `SKIP_ALREADY_ANALYZED_RFC = False` in `config.py`, or
2. delete `process_log.json`.

---

# 2. New-address-discovery

`New-address-discovery` is the runtime component for IPv6 active probing. It takes probing mechanism reports and converts them into protocol plugins. The compiled probing program then sends packets and records responsive IPv6 addresses.

The component supports two input modes:

1. **Prefix mode**: input lines are IPv6 prefixes, such as `2001:db8::/32`.
2. **Exact-address mode**: input lines are exact IPv6 addresses, such as `2001:db8::1`.

If every input line is an exact IPv6 address, the program probes each address once. If the input contains prefixes, the program uses budget-based randomized probing.

---

## Main Directory Details

### `input/`

This folder contains target files.

Example prefix input:

```text
2001:db8::/32
2400:3200::/32
2a00:1450::/32
```

Example exact-address input:

```text
2001:db8::1
2001:db8::2
2001:db8::3
```

Common files in this project:

```text
input/BGP_prefixes.txt
input/Hitlist_prefixes.txt
input/test.txt
input/res0.txt
```

### `ipv6_probes/`

This folder contains the RFC analysis reports generated by `RFC-codegen`. These files are used as input by the LLM-based plugin generator.

### `protocols/`

Each subdirectory is one protocol plugin. For example:

```text
protocols/ack_rst/
|-- ack_rst.c
`-- ack_rst.h
```

A plugin must provide two functions:

```c
int <protocol_name>_build_probe(...);
int <protocol_name>_parse_response(...);
```

Each plugin also registers itself through the framework registry so that it can be selected by name at runtime.

Existing protocol examples include:

```text
ack_rst
syn_rst
tcp_probe
tcp_syn_ack
udp_icmp
dns_probe
http_probe
multicast_probing
neighbor_solicitation_and_advertisement
subnet_router_anycast_probing
```

### `src/`

This folder contains the core probing framework.

Important files:

- `main.c`: command-line parsing, raw socket setup, sending loop, receiving thread, and result logging.
- `construct.c`: packet construction helpers for IPv6/TCP/ICMPv6 probing.
- `parser.c`: parses prefix input and exact-address input.
- `protocol_loader.c`: loads a selected protocol plugin by name.
- `protocol_registry.c`: maintains the protocol plugin registry.
- `hash.c`: hash function used for embedding and checking probe identifiers.
- `sample.c`: adaptive sampling helpers for probing logic.

### `include/`

This folder contains shared header files used by the C framework and plugins.

Important files:

- `config.h`: global configuration, prefix table definitions, and runtime variables.
- `protocol.h`: protocol plugin interface and registry API.
- `construct.h`: packet construction API.
- `parser.h`: input parsing API.
- `hash.h`: hash API.
- `sample.h`: sampling API.

---

## Step 1: Generate Protocol Plugins

If the `protocols/` directory already contains the protocol plugins you need, you can skip this step.

### Generate plugins from one RFC report

Edit this variable in `llm_protocol_builder.py`:

```python
RFC_ANALYSIS_FILE = "ipv6_probes/rfc4294.txt"
```

Then run:

```bash
cd New-address-discovery
python3 -m pip install requests
python3 llm_protocol_builder.py
```

The generated plugin will be written into:

```text
protocols/<protocol_name>/
```

### Generate plugins from multiple RFC reports

Edit this variable in `generate_plugins.py`:

```python
RFC_ANALYSIS_DIR = "ipv6_probes"
```

Then run:

```bash
python3 generate_plugins.py
```

The script reads all `.txt` files in the selected RFC analysis directory, extracts mechanisms, removes duplicate names, and generates protocol plugin folders under `protocols/`.

---

## Step 2: Configure Runtime Network Parameters

Before running probes, edit `run.sh` and `run_all_protocols.sh`.

The following values must match your machine and network environment:

```bash
INTERFACE_NAME="ens17f0"
SOURCE_MAC="80:61:5f:2b:cb:9b"
SOURCE_IP="2402:f000:6:1e00::233"
GATEWAY_MAC="74:ea:c8:b4:24:d4"
```

You can check your network interface and addresses with:

```bash
ip link
ip -6 addr
ip -6 route
```

The program uses raw Ethernet sockets, so an incorrect interface name, source MAC, source IPv6 address, or gateway MAC will prevent probes from working correctly.

---

## Step 3: Build the Probing Program

From `New-address-discovery/`:

```bash
make clean
make
```

The executable will be generated at:

```text
bin/main
```

---

## Step 4: Run One Protocol

Use `run.sh` to run one selected protocol plugin.

Basic usage:

```bash
sudo ./run.sh <protocol_name> [input_file] [output_file]
```

Example:

```bash
sudo ./run.sh ack_rst input/test.txt output/ack_rst.log
```

If no input file or output file is provided, `run.sh` uses:

```text
input/test.txt
output/test.log
```

The output file contains discovered responsive IPv6 addresses, one address per line.

---

## Step 5: Run All Protocols

Use `run_all_protocols.sh` to run every protocol plugin under `protocols/`:

```bash
sudo ./run_all_protocols.sh
```

By default, this script uses:

```text
input/BGP_prefixes.txt
logs/<protocol_name>.log
```

Each protocol writes its own result log under `logs/`.

---

## Step 6: Count Unique Discovered IPv6 Addresses

After probing, use `count_unique_ipv6.py` to remove duplicate addresses and count unique results.

Example:

```bash
python3 count_unique_ipv6.py output/ack_rst.log output/ack_rst.unique.txt
```

The script prints:

- total number of lines
- number of unique IPv6 addresses
- number of duplicate lines
- most frequent duplicate addresses

---

## Direct Runtime Command

The compiled binary can also be called directly:

```bash
sudo bin/main \
  <protocol> \
  <interface_name> \
  <source_mac> \
  <source_ip> \
  <gateway_mac> \
  <input_filename> \
  <output_filename>
```

Example:

```bash
sudo bin/main \
  ack_rst \
  ens17f0 \
  80:61:5f:2b:cb:9b \
  2402:f000:6:1e00::233 \
  74:ea:c8:b4:24:d4 \
  input/test.txt \
  output/ack_rst.log
```

---

## End-to-End Example

The following commands show a typical run from RFC analysis to IPv6 probing.

```bash
# 1. Analyze RFC documents
cd RFC-codegen
python3 -m pip install openai requests tiktoken
python3 main.py

# 2. Copy or reuse generated reports in New-address-discovery/ipv6_probes
cd ../New-address-discovery

# 3. Generate protocol plugins if needed
python3 -m pip install requests
python3 llm_protocol_builder.py

# 4. Build the probing framework
make clean
make

# 5. Run one protocol
sudo ./run.sh ack_rst input/test.txt output/ack_rst.log

# 6. Count unique discovered addresses
python3 count_unique_ipv6.py output/ack_rst.log output/ack_rst.unique.txt
```

---

## Output Summary

### RFC-codegen output

```text
RFC-codegen/ipv6_probes/rfcXXXX.txt
```

These files describe IPv6 probing mechanisms extracted from RFC documents.

### New-address-discovery output

```text
New-address-discovery/output/*.log
New-address-discovery/logs/*.log
```

These files contain discovered responsive IPv6 addresses.

---

## Troubleshooting

### `make` reports `implicit declaration of function 'load_protocol'`

Some GCC versions treat missing function declarations as compilation errors. If this happens, add the following declaration to `include/protocol.h`:

```c
void load_protocol(const char *name);
```

Then rebuild:

```bash
make clean
make
```

### `Executable not found. Please compile the project first using 'make'.`

Run:

```bash
make clean
make
```

Then run `run.sh` again.

### `Unknown protocol: <name>`

The protocol name must match a registered plugin name under `protocols/`.

Check available protocol directories:

```bash
ls protocols/
```

Then run with one of those names, for example:

```bash
sudo ./run.sh ack_rst
```

### `socket: Operation not permitted`

The probing program uses raw sockets. Run it with root privileges:

```bash
sudo ./run.sh ack_rst
```

### No responses are received

Check the following items:

1. The network interface name is correct.
2. The source MAC address is correct.
3. The source IPv6 address is assigned to the selected interface.
4. The gateway MAC address is correct.
5. The input file contains valid IPv6 prefixes or exact IPv6 addresses.
6. The selected protocol is suitable for the target network.

---

## Notes

- `RFC-codegen` requires an LLM API to extract probing mechanisms.
- `New-address-discovery` requires root privileges because it sends and receives raw IPv6 packets.
- `run.sh` and `run_all_protocols.sh` contain hard-coded network parameters that must be changed before running on a different host.
- Large-scale active probing may generate a high packet rate. Configure the target input and probing environment carefully.
