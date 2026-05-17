import tempfile
import shutil

filename = "/home/zjs/Helixir20260102/Data/aliased-prefixes.txt"

with open(filename, "r", encoding="utf-8") as fin, \
     tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as fout:
    
    next(fin) 
    for line in fin:
        fout.write(line)

shutil.move(fout.name, filename)
