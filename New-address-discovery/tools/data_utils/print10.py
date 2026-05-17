input_file_path = '/home/zjs/Helixir20260102/Data/aliased-prefixes.txt'

with open(input_file_path, 'r') as file:
    cnt = 0
    for line in file:
        line = line.strip()
        cnt = cnt + 1
        if cnt < 10:
            # break
            print(line)
print(cnt)