from collections import Counter
from pathlib import Path
import sys

if len(sys.argv) < 2:
    print("Usage: python3 count_unique_ipv6.py <input_file> [unique_output_file]")
    sys.exit(1)

input_file = Path(sys.argv[1])
output_file = Path(sys.argv[2]) if len(sys.argv) >= 3 else input_file.with_suffix(".unique.txt")

counter = Counter()
total = 0

with input_file.open("r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        addr = line.strip()
        if not addr:
            continue
        counter[addr] += 1
        total += 1
        if total % 100000 == 0:
            print(f"已读取 {total} 行，当前唯一地址 {len(counter)} 个", flush=True)

with output_file.open("w", encoding="utf-8") as f:
    for addr in counter.keys():
        f.write(addr + "\n")

unique = len(counter)
print(f"输入文件: {input_file}")
print(f"总行数: {total}")
print(f"去重后地址数: {unique}")
print(f"重复行数: {total - unique}")
print(f"去重结果已保存到: {output_file}")

print("\n重复最多的前 20 个地址:")
for addr, count in counter.most_common(20):
    if count <= 1:
        break
    print(f"{addr}  {count}")