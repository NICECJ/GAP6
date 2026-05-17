# 6Genos: Discovering Active IPv6 Addresses in Seedless Scenarios

<img width="920" alt="image" src="https://github.com/user-attachments/assets/18081a54-f236-47b3-a41e-82297114b281" />

6Genos is a system for active IPv6 address discovery in seedless scenarios.   Active address probing is fundamental to large-scale network measurement, asset discovery, and security assessment.   Although scenarios with seed addresses have witnessed substantial progress, research in seedless scenarios remains nascent, hindered by a lack of general patterns and the restricted applicability of probing methods.

## Overview

6Genos addresses the challenge of discovering active IPv6 addresses in seedless scenarios by leveraging the core assumption that address configuration exhibits generality—patterns learned from seeded prefixes are also applicable in seedless scenarios.   The system operates in three main stages:

1.   **Pattern Extraction**: Extracts patterns from seed addresses at multiple granularities and identifies general ones to form a pattern library
2.   **Graph Construction**: Constructs a General Pattern Genealogy Graph (GPGG) to model hierarchical relationships among patterns across different granularities
3.   **Heuristic Dynamic Migration Probing**: Adopts an adaptive probing strategy that incorporates feedback to achieve precise pattern matching and optimal resource utilization

## Features

- **Multi-granularity Pattern Extraction**: Extracts and organizes patterns at different star levels (1-5 stars)
- **General Pattern Genealogy Graph**: Models hierarchical relationships between patterns across granularities
- **Adaptive Probing Strategy**: Dynamically adjusts scanning based on hit rates and feedback
- **Seedless BGP Prefix Support**: Discovers active addresses in prefixes without seed addresses

## Project Structure

```
6Genos/
├── gen_nodes.py          # Generate graph structure and node relationships
├── try_method.py         # Main execution script
├── graph_enhanced.pkl    # Pre-built graph structure
└── README.md
```

## Requirements

### Dependencies

- Python 3.x
- Required packages:

### External Tools

- **smap**: IPv6 scanning tool (required for address scanning)
- https://github.com/AddrMiner/smap

### Data Files

- **Graph file**: `graph_enhanced.pkl` 
- **BGP prefix list**: `test.txt` 

## Installation

1.   Install Python 3.x
2.   Install and configure `smap` for IPv6 scanning
3.   Prepare data files (graph file and BGP prefix list)

## Usage

### Quick Start

Run the main script:

```bash
python3 try_method.py
```

### Configuration Parameters

The main parameters in `try_method.py` can be adjusted:

- **`file_path`**: Path to graph structure file (default: `./graph_enhanced.pkl`)
- **BGP prefix file**: Path to BGP prefix list (default: `./test.txt`)
- **`buget_per_bgp`**: Budget per BGP prefix for scanning
- **`MAX_ROUNDS_PER_BGP`**: Maximum number of probing rounds per BGP prefix
- **`TOP_NODES_COUNT`**: Number of top nodes to select per round
- **`NODE_REWARD_THRESHOLD`**: Threshold for node reward filtering
- **`PRE_SCAN_COUNT`**: Pre-scanning counts for different star levels
- **`TOP_NODES_BY_STAR`**: Number of top nodes to select per star level

### Workflow

1.   **Graph Generation** (It's not necessary if you want to use the already constructed graph):
```bash
python gen_nodes.py
```
Generates the GPGG from pattern files and saves as `graph_enhanced.pkl`.

2.   **Run Discovery**:
```bash
python3 try_method.py
```
The script will:
- Load the graph structure
- Read BGP prefixes from the input file
- For each prefix, perform initial probing and adaptive rounds
- Generate candidate addresses based on pattern matching
- Scan addresses using `smap`
- Update node rewards based on hit rates
- Save discovered active addresses

## How It Works

1.   **Pattern Library Construction**:
- Extracts patterns from seeded prefixes at multiple granularities
- Selects general patterns using designed principles
- Builds a pattern library

2.   **GPGG Construction**:
- Models hierarchical relationships between patterns
- Establishes cross-granularity connections
- Organizes patterns into families

3.   **Dynamic Migration Probing**:
- Starts with initial probing of selected nodes
- Generates candidate addresses by combining BGP prefixes with patterns
- Scans addresses and collects feedback
- Updates node rewards based on hit rates
- Adaptively migrates to promising child nodes
- Continues for multiple rounds until budget or convergence criteria are met

