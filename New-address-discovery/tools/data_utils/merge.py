#!/usr/bin/env python3

from pathlib import Path
import ipaddress

# ================== Configuration ==================

INPUT_FILES = [
    "/home/zjs/Helixir20260102/Helixir_ACK_RST/output/useful_non_frp_ipv6.log",
    "/home/zjs/Helixir20260102/Helixir_SYN_RST/output/useful_non_frp_ipv6.log",
    "/home/zjs/Helixir20260102/Helixir_UDP_ICMP/output/useful_non_frp_ipv6.log"
]

OUTPUT_FILE = "/home/zjs/Helixir20260102/Data/all.log"

# Index of the field to extract (0-based)
TARGET_FIELD_INDEX = 0

# ================== Core Logic ==================

def merge_and_deduplicate(files, output_file, field_index=0):
    """
    Merge multiple files, extract a specific field (IPv6 addresses),
    remove duplicates, skip empty or invalid IPv6 addresses,
    and write deduplicated addresses to output_file.
    Also prints how many duplicates were removed.
    """
    unique_addresses = set()
    total_addresses = 0
    stats = {}

    for file_path in files:
        file_path = Path(file_path)
        stats[file_path] = {"total_lines": 0, "valid_lines": 0, "skipped_invalid": 0}

        if not file_path.exists():
            print(f"[WARN] File not found: {file_path}")
            continue

        with file_path.open("r") as f:
            for line in f:
                stats[file_path]["total_lines"] += 1
                parts = line.strip().split()
                if len(parts) <= field_index:
                    continue  # Not enough fields

                candidate = parts[field_index].strip()
                if not candidate:
                    continue  # Skip empty field

                # Validate IPv6
                try:
                    ip = ipaddress.IPv6Address(candidate)
                except ipaddress.AddressValueError:
                    stats[file_path]["skipped_invalid"] += 1
                    continue

                total_addresses += 1
                unique_addresses.add(str(ip))
                stats[file_path]["valid_lines"] += 1

    # Write deduplicated valid addresses to output
    output_file = Path(output_file)
    with output_file.open("w") as out:
        for addr in sorted(unique_addresses):
            out.write(addr + "\n")

    duplicates_removed = total_addresses - len(unique_addresses)

    # Print summary
    print(f"\n[OK] Output written to: {output_file}")
    print(f"[OK] Total valid IPv6 addresses processed: {total_addresses}")
    print(f"[OK] Unique valid IPv6 addresses       : {len(unique_addresses)}")
    print(f"[OK] Duplicates removed                : {duplicates_removed}\n")

    for file_path, s in stats.items():
        print(f"{file_path}")
        print(f"  Total lines       : {s['total_lines']}")
        print(f"  Valid IPv6 lines  : {s['valid_lines']}")
        print(f"  Skipped invalid   : {s['skipped_invalid']}")
        print()

# ================== Entry Point ==================

if __name__ == "__main__":
    merge_and_deduplicate(
        files=INPUT_FILES,
        output_file=OUTPUT_FILE,
        field_index=TARGET_FIELD_INDEX,
    )
