import ipaddress


FILE1 = "/home/zjs/Helixir20260102/Helixir_SYN_RST/output/useful.log"
FILE2 = "/home/zjs/Helixir20260102/Helixir_ACK_RST/output/useful.log"


def load_ipv6_set(filename):
    ipv6_set = set()
    total = 0

    with open(filename, "r") as f:
        for line in f:
            ip = line.strip()
            if not ip:
                continue
            try:
                ipaddress.IPv6Address(ip)
                ipv6_set.add(ip)
                total += 1
            except ipaddress.AddressValueError:
                continue

    return ipv6_set, total


def main():
    set1, total1 = load_ipv6_set(FILE1)
    set2, total2 = load_ipv6_set(FILE2)

    common_count = len(set1 & set2)

    ratio1 = common_count / total1 if total1 > 0 else 0.0
    ratio2 = common_count / total2 if total2 > 0 else 0.0

    print(f"File1 total IPv6 addresses: {total1}")
    print(f"File2 total IPv6 addresses: {total2}")
    print(f"Common IPv6 addresses: {common_count}")
    print(f"Common / File1 ratio: {ratio1:.6f}")
    print(f"Common / File2 ratio: {ratio2:.6f}")


if __name__ == "__main__":
    main()
