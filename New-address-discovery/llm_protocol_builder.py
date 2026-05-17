#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import requests

API_KEY = "sk-dpdlutirghtwgvgbdnzrblzkrkvidbngcpyyjftoknlnltpb"
MODEL = "deepseek-ai/DeepSeek-V3"

# analyzed from RFC (IPv6 Node Requirements)
RFC_ANALYSIS_FILE = "ipv6_probes/rfc4294.txt"

# few-shot example
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ACK_RST_H = os.path.join(BASE_DIR, "protocols", "ack_rst", "ack_rst.h")
ACK_RST_C = os.path.join(BASE_DIR, "protocols", "ack_rst", "ack_rst.c")

# generated protocol plugins will be saved in this directory
BASE_PROTOCOL_DIR = os.path.join(BASE_DIR, "protocols")

API_URL = "https://api.siliconflow.cn/v1/chat/completions"

def normalize_name(name: str) -> str:
    """Convert mechanism name to folder/file name"""
    name = name.lower()
    name = re.sub(r'[^a-z0-9]+', '_', name)
    return name.strip("_")


def parse_mechanisms(text):
    """Extract mechanisms from RFC analysis output"""
    mechanisms = []

    blocks = re.split(r'Mechanism \d+:', text)

    for block in blocks[1:]:
        name_match = re.search(r'Mechanism Name:\s*(.+)', block)
        protocol_match = re.search(r'Protocol:\s*(.+)', block)
        packet_flow_match = re.search(r'Packet Flow:\s*(.+)', block)
        receive_filter_match = re.search(r'Receive Filter:\s*(.+)', block)
        fields_match = re.search(r'Fields To Modify:\s*(.+)', block)

        if not name_match:
            continue

        mechanisms.append({
            "name": name_match.group(1).strip(),
            "protocol": protocol_match.group(1).strip() if protocol_match else "",
            "packet_flow": packet_flow_match.group(1).strip() if packet_flow_match else "",
            "receive_filter": receive_filter_match.group(1).strip() if receive_filter_match else "",
            "fields": fields_match.group(1).strip() if fields_match else ""
        })

    return mechanisms


def load_example():
    """Load ack_rst example for few-shot"""
    with open(ACK_RST_H) as f:
        ack_h = f.read()
    with open(ACK_RST_C) as f:
        ack_c = f.read()
    return ack_h, ack_c


def build_prompt(mechanism, example_h, example_c):
    mech_name = normalize_name(mechanism["name"])

    return f"""
You are a network systems programmer.

You are generating a protocol plugin for an IPv6 probing framework.

Below is an example plugin (ack_rst):

================================================
EXAMPLE HEADER (ack_rst.h)
================================================

{example_h}

================================================
EXAMPLE SOURCE (ack_rst.c)
================================================

{example_c}

================================================
Your task:
Generate a NEW plugin using the SAME coding style and architecture.

The new mechanism is:

Mechanism Name:
{mechanism["name"]}

Protocol:
{mechanism["protocol"]}

Packet Flow:
{mechanism["packet_flow"]}

Receive Filter:
{mechanism["receive_filter"]}

Fields To Modify:
{mechanism["fields"]}

================================================

Requirements:

1. Follow the SAME structural design as ack_rst.
2. Keep coding style consistent.
3. Use clean, concise naming (avoid overly long identifiers).
4. Provide two files:
   {mech_name}.h
   {mech_name}.c
5. Functions must follow this pattern:
   - {mech_name}_build_probe
   - {mech_name}_parse_response

6. The parse_response() function must:
   - Validate packet type
   - Extract target IPv6 address
   - Verify embedded checksum using murmur3
   - Perform bloom filter deduplication

7. Keep implementation modular and consistent with the example.

================================================

Output format EXACTLY:

###HEADER###
<full header file>

###SOURCE###
<full source file>
"""

def call_llm(prompt):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": "You generate C network probing plugins."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }

    r = requests.post(API_URL, headers=headers, json=data)
    if r.status_code != 200:
        raise Exception(f"LLM API error: {r.text}")

    return r.json()["choices"][0]["message"]["content"]

def save_protocol(name, output):
    header_match = re.search(r'###HEADER###(.*?)###SOURCE###', output, re.S)
    source_match = re.search(r'###SOURCE###(.*)', output, re.S)

    if not header_match or not source_match:
        print("⚠ LLM output format error")
        return

    header_code = header_match.group(1).strip()
    source_code = source_match.group(1).strip()

    folder = os.path.join(BASE_PROTOCOL_DIR, name)
    os.makedirs(folder, exist_ok=True)

    h_path = os.path.join(folder, f"{name}.h")
    c_path = os.path.join(folder, f"{name}.c")

    with open(h_path, "w") as f:
        f.write(header_code)
    with open(c_path, "w") as f:
        f.write(source_code)

    print(f"✔ Generated: {h_path}")
    print(f"✔ Generated: {c_path}")

def main():
    print("Reading RFC analysis...")

    with open(RFC_ANALYSIS_FILE) as f:
        text = f.read()

    mechanisms = parse_mechanisms(text)
    print(f"Found {len(mechanisms)} mechanism(s)")

    example_h, example_c = load_example()

    for mech in mechanisms:
        name = normalize_name(mech["name"])
        print(f"\nGenerating protocol plugin: {name}")

        prompt = build_prompt(mech, example_h, example_c)
        output = call_llm(prompt)
        save_protocol(name, output)


if __name__ == "__main__":
    main()