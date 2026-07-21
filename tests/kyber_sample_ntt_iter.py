# ./kyber_sample_ntt_iter | python3 kyber_sample_ntt_iter.py

import sys
import json

iterations = None
sum = 0

for line in sys.stdin:
    line = line.rstrip("\n")
    if iterations is None:
        iterations = int(line)
    else:
        sum += int(line)

avg = round(sum / iterations)

result = {
    "config": {"iterations": iterations},
    "stats": {"avg": avg},
}

with open("kyber_sample_ntt_iter.json", "w+") as f:
    f.write(json.dumps(result, indent="\t", sort_keys=True))
