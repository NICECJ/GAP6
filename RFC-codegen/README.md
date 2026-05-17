# RFC IPv6 Probing Mechanism Analyzer

This tool automatically analyzes RFC documents and extracts protocol behaviors that can be used for **active IPv6 address probing**.

The extracted mechanisms are structured so that they can be directly used by another large language model to generate **packet sending and receiving code**.

## Features

- Automatic RFC document parsing (XML and TXT)
- Intelligent document cleaning and section splitting
- LLM-based protocol behavior extraction
- RFC-level deduplication and aggregation
- Structured probing mechanism generation

## Project Structure

```
project/
│
├── RFC/                    # Downloaded RFC documents
├── ipv6_probes/            # Generated probing mechanism reports
│
├── main.py                 # Program entry point
├── pipeline.py             # End-to-end processing pipeline
│
├── analyzer.py             # Stage 1: chunk-level candidate extraction
├── aggregator.py           # Stage 2: RFC-level mechanism aggregation
│
├── rfc_parser.py           # RFC XML/TXT parser
├── cleaner.py              # Document cleaning module
├── splitter.py             # RFC text splitting module
├── metadata_filter.py      # RFC metadata filtering
│
├── downloader.py           # RFC automatic download
├── config.py               # Configuration file
│
├── requirements.txt
└── README.md
```

## Installation

### Create Virtual Environment (Optional)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install openai tiktoken requests
```

## Configuration

Edit `config.py` or the configuration section in `main.py`.

### API Configuration

```python
API_KEY = "your_api_key"
BASE_URL = "https://api.siliconflow.cn/v1"
MODEL = "Qwen/Qwen2.5-72B-Instruct"
LLM_TEMPERATURE = 0.1
```

### Supported Providers

| Provider    | BASE_URL                      | MODEL                     |
| ----------- | ----------------------------- | ------------------------- |
| SiliconFlow | https://api.siliconflow.cn/v1 | Qwen/Qwen2.5-72B-Instruct |
| DeepSeek    | https://api.deepseek.com      | deepseek-chat             |
| OpenAI      | https://api.openai.com/v1     | gpt-3.5-turbo             |

## Usage

### Run the Main Program

```bash
python main.py
```

### Processing Workflow

1. Download RFC documents
2. Parse and clean RFC text
3. Split documents into manageable chunks
4. Extract probing candidates using LLM
5. Aggregate candidates into final mechanisms
6. Generate probing reports

## Output

For each RFC containing usable mechanisms, a report is generated:

```
ipv6_probes/rfcXXXX.txt
```

### Report Structure

Each report includes:

- Mechanism name
- Protocol stack information
- Packet template
- Fields to modify
- Packet flow
- Receive filter
- Success and failure conditions
- RFC reference sentence

These outputs are designed to be directly consumable by another LLM that generates packet probing code.

## Processing Pipeline

The system uses a two-stage extraction architecture.

### Stage 1: Candidate Extraction

**Module:** `analyzer.py`

- Operates on individual RFC text chunks
- Extracts possible probing behaviors
- Results may contain duplicates or partial interpretations

### Stage 2: Mechanism Aggregation

**Module:** `aggregator.py`

- Aggregates all candidates from the same RFC
- Removes duplicates
- Merges similar rules
- Filters impractical probing mechanisms
- Produces final RFC-level probing methods

## Example Output

```
Mechanism Name: ICMPv6_Echo_Reply

Protocol: ICMPv6

Condition: Target receives an ICMPv6 Echo Request

Packet Flow: Echo Request -> Echo Reply

Network Layer Protocol: IPv6
Transport Layer Protocol: None
Application Layer Protocol: None

Template Base: Standard ICMPv6 Echo Request

Fields To Modify:
{
  "network_layer": ["destination IPv6 address"],
  "transport_layer": [],
  "application_layer": []
}

Receive Filter: ICMPv6 Echo Reply from target

Success Condition: Valid Echo Reply received
```

## Intended Use

This tool is designed for:

- IPv6 active measurement research
- Network protocol analysis
- Automated probing method discovery
- LLM-assisted packet generation pipelines
