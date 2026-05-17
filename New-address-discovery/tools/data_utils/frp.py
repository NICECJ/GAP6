#!/usr/bin/env python3

"""
This script processes IPv6 addresses against aliased prefixes.
It loads aliased prefixes into a SubnetTree, then checks each IP address.
IPv6 addresses not matching any aliased prefix are written to an output file.
"""

import sys
import ipaddress

try:
    import SubnetTree
except Exception as e:
    print(e, file=sys.stderr)
    print("Use `pip install pysubnettree`", file=sys.stderr)
    sys.exit(1)


PREFIX_FILE = "/home/zjs/Helixir20260102/Data/aliased-prefixes.txt"
IP_FILE = "/home/zjs/Helixir20260102/Helixir_UDP_ICMP/output/useful.log"
NON_FRP_FILE = "/home/zjs/Helixir20260102/Helixir_UDP_ICMP/output/useful_non_frp_ipv6.log"


def fill_tree(tree, file_handle, suffix=",1"):
    """
    Load prefixes from file_handle into the subnet tree.
    Each prefix is annotated with a suffix (e.g., ',1' for aliased).
    """
    count = 0
    for line in file_handle:
        line = line.strip()
        if not line:
            continue
        count += 1
        try:
            ipaddress.ip_network(line, strict=False)  # validate
            tree[line] = line + suffix
        except ValueError:
            print(f"Invalid prefix skipped: {line}", file=sys.stderr)
    return tree


def read_aliased(tree, file_path):
    """
    Read aliased prefixes from a file and load them into the tree.
    """
    with open(file_path, "r") as f:
        tree = fill_tree(tree, f, suffix=",1")
    return tree


def main():
    tree = SubnetTree.SubnetTree()
    # Load aliased prefixes
    tree = read_aliased(tree, PREFIX_FILE)

    total = 0
    in_prefix = 0
    not_in_prefix = 0

    with open(IP_FILE, "r") as fin, open(NON_FRP_FILE, "w") as fout:
        for line in fin:
            ip = line.strip()
            if not ip:
                continue

            total += 1
            if total % 10000 == 0:
                print(f"Processed {total} addresses...")

            try:
                ipaddress.IPv6Address(ip)
            except ipaddress.AddressValueError:
                print(f"Invalid IPv6 skipped: {ip}", file=sys.stderr)
                continue

            try:
                _ = tree[ip]  # match found in aliased prefixes
                in_prefix += 1
            except KeyError:
                not_in_prefix += 1
                fout.write(ip + "\n")

            if total % 1_000_000 == 0:
                print(f"Processed {total} addresses...")

    print("===== Result =====")
    print(f"Total IPv6 addresses : {total}")
    print(f"In aliased prefixes  : {in_prefix}")
    print(f"Not in prefixes      : {not_in_prefix}")
    print(f"Output file          : {NON_FRP_FILE}")


if __name__ == "__main__":
    main()
