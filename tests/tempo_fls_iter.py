# ./tempo_fls_iter | python3 tempo_fls_iter.py

import sys
import json

MIN = 128
MAX = 280

iterations = None
data = {}

for line in sys.stdin:
    line = line.rstrip("\n")
    if iterations is None:
        iterations = int(line)
    else:
        if line not in data:
            data[line] = 1
        else:
            data[line] += 1

result = {
    "config": {"min": MIN, "max": MAX, "iterations": iterations},
    "data": data,
}

with open("tempo_fls_iter.json", "w+") as f:
    f.write(json.dumps(result, indent="\t", sort_keys=True))
