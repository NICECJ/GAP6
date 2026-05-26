#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import requests

API_KEY = "sk-dpdlutirghtwgvgbdnzrblzkrkvidbngcpyyjftoknlnltpb"
MODEL = "deepseek-ai/DeepSeek-V3"

# directory containing RFC analysis txt files
RFC_ANALYSIS_DIR = "ipv6_probes_test"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ACK_RST_H = os.path.join(BASE_DIR, "protocols", "ack_rst", "ack_rst.h")
ACK_RST_C = os.path.join(BASE_DIR, "protocols", "ack_rst", "ack_rst.c")

# generated protocol plugins directory
BASE_PROTOCOL_DIR = os.path.join(BASE_DIR, "protocols")

API_URL = "https://api.siliconflow.cn/v1/chat/completions"


def normalize_name(name: str) -> str:
    """Convert mechanism name to folder/file name"""
    name = name.lower()
    name = re.sub(r'[^a-z0-9]+', '_', name)
    return name.strip("_")


def load_all_rfc_files():
    """Load all txt files from RFC directory"""
    files = []

    for f in os.listdir(RFC_ANALYSIS_DIR):
        if f.endswith(".txt"):
            files.append(os.path.join(RFC_ANALYSIS_DIR, f))

    return files


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

1. Use the current plugin architecture exactly.
   - The plugin must expose one protocol_t instance named {mech_name}_protocol.
   - The protocol name must be exactly "{mech_name}".
   - It must register itself with __attribute__((constructor)) and register_protocol().
   - It must implement:
     int {mech_name}_build_probe(struct ethhdr *eth, struct ip6_hdr *ip6, void *l4, int prefix_index)
     int {mech_name}_parse_response(uint8_t *buffer, ssize_t len, struct in6_addr *target_ip, uint64_t *prefix_index)
   - Use casts only if needed to match protocol_t.

2. Respect the framework boundary.
   - build_probe() only builds one packet in eth/ip6/l4.
   - parse_response() only validates one received packet and returns 1/0.
   - Do NOT open files, write output files, print per-packet logs, create sockets, call send/recv, sleep, fork, run shell commands, update total_hits, or manage threads.
   - Do NOT implement final unique-address counting in the plugin. main.c performs exact unique-address deduplication, output writing, and final [probe_result] reporting.
   - Do NOT copy ack_rst's legacy Bloom-filter deduplication helper into new plugins; duplicate suppression belongs to main.c.

3. Support both target modes.
   - exact-address mode: if exact_addr_flags[prefix_index] is true, build_probe() must use exact_addr_table[prefix_index] as ip6_dst directly.
   - prefix-generation mode: if exact_addr_flags[prefix_index] is false, generate the destination address using prefix_table[prefix_index].prefix_stub, mask_suffix, a random middle suffix, and the existing murmur3 checksum rule:
     last 32 bits == murmur3(first 96 bits, seed 0x11112222).
   - Never require a 6Genos exact address to satisfy the murmur3 checksum rule.

4. Response parsing must work in both modes.
   - Validate len before every header access.
   - Validate Ethernet type and IPv6 next-header values using struct fields, not magic byte offsets.
   - Extract the discovered IPv6 address into *target_ip.
   - In exact-address mode, accept the response if the discovered address exactly matches one entry in exact_addr_table; set *prefix_index to that matched index.
   - In prefix-generation mode, verify the embedded murmur3 checksum before accepting the response; recover *prefix_index from a field intentionally encoded by build_probe(), and reject if it is >= prefix_table_size.

5. Packet construction constraints.
   - Use the global runtime config variables from config.h: source_mac, gateway_mac, source_ip, prefix_table, exact_addr_flags, exact_addr_table.
   - Do not hard-code interface names, local MACs, gateway MACs, source IPv6 addresses, file paths, or BGP prefixes.
   - Initialize eth, ip6, and the L4 storage with memset before filling fields.
   - Current main.c passes a 20-byte L4 buffer and copies sizeof(struct tcphdr). Therefore the generated probe must fit its L4 header/state into that buffer and must not require payload bytes beyond it.
   - If the RFC mechanism requires a payload, extension-header chain, or variable-length packet that cannot fit this framework, generate the safest minimal header-only probe and clearly leave a short C comment explaining the limitation.

6. Checksums and protocol correctness.
   - Compute IPv6 TCP/UDP/ICMPv6 checksums with an IPv6 pseudo-header when the protocol requires it.
   - For TCP-like probes, either call constructTCPv6Packet() and then adjust flags/ports safely, or reproduce equivalent initialization and checksum logic.
   - If build_probe() changes TCP flags, ports, or sequence fields after constructTCPv6Packet(), recompute the TCP checksum.
   - Encode prefix_index in a protocol-specific request field so parse_response() can map valid responses back to the source prefix.

7. Code quality.
   - Keep the code self-contained in {mech_name}.h and {mech_name}.c.
   - Include only headers that are actually needed.
   - Use static helper functions for repeated logic such as exact-address matching, checksum calculation, target address construction, and MAC parsing.
   - Avoid undefined behavior from unaligned pointer casts when reading packet bytes; prefer memcpy where alignment may be uncertain.
   - The code must compile with the existing Makefile and CFLAGS.
   - Keep names concise and consistent with {mech_name}.

8. Output only the two requested files. Do not include explanations outside the required markers.

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
    print("Reading RFC analysis files...")

    files = load_all_rfc_files()

    all_mechanisms = []
    seen = set()

    for file in files:

        print(f"Reading {file}")

        with open(file) as f:
            text = f.read()

        mechanisms = parse_mechanisms(text)

        print(f"Found {len(mechanisms)} mechanism(s)")

        for mech in mechanisms:
            name = normalize_name(mech["name"])

            if name in seen:
                continue

            seen.add(name)
            all_mechanisms.append(mech)

    print(f"\nTotal unique mechanisms: {len(all_mechanisms)}")

    example_h, example_c = load_example()

    for mech in all_mechanisms:

        name = normalize_name(mech["name"])

        print(f"\nGenerating protocol plugin: {name}")

        prompt = build_prompt(mech, example_h, example_c)

        output = call_llm(prompt)

        save_protocol(name, output)


if __name__ == "__main__":
    main()