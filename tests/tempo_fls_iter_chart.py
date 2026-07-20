import json
import matplotlib.pyplot as plt
import numpy as np

with open("tempo_fls_iter.json") as f:
    data = json.loads(f.read())
    config = data["config"]
    min = int(config["min"])
    max = int(config["max"])

ctr = [0] * (max - min + 1)
for iter, count in data["data"].items():
    ctr[int(iter) - min] = count

x = np.linspace(min, max, len(ctr))
y = np.array(ctr)

fig, ax = plt.subplots()
ax.set_title(
    f"Distribution of effective iterations in Tempo FLS polynomial sampling", pad=10
)
ax.plot(x, y)

plt.savefig("tempo_fls_iter.png")
