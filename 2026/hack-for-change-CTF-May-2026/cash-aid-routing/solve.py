import math
import json
import urllib.request
import urllib.parse

seed = "967d2edbd5e7f3d5a19dee7399662ccb9513df27eeeeec0d637e5e918c00fd1e"
url = f"https://hackforachangeruntime.vercel.app/api/cash-aid-routing?seed={seed}&action=instance"

res = urllib.request.urlopen(url).read()
data = json.loads(res)

villages = {v["id"]: v for v in data["villages"]}
threshold = data["max_total_distance"]

depot = villages[0]
points = {i: (v["x"], v["y"]) for i, v in villages.items()}

def dist(a, b):
    return math.sqrt((a[0]-b[0])**2 + (a[1]-b[1])**2)

# Nearest neighbor from depot
unvisited = set(range(1, 26))
tour = []
current = 0
while unvisited:
    best = min(unvisited, key=lambda v: dist(points[current], points[v]))
    tour.append(best)
    unvisited.remove(best)
    current = best

# Return to depot
total = dist(points[0], points[tour[0]]) + dist(points[tour[-1]], points[0])
for i in range(len(tour)-1):
    total += dist(points[tour[i]], points[tour[i+1]])

print(f"Tour: {tour}")
print(f"Total distance: {total:.4f}")
print(f"Threshold: {threshold}")
print(f"Under threshold: {total < threshold}")

if total < threshold:
    verify_url = f"https://hackforachangeruntime.vercel.app/api/cash-aid-routing?seed={seed}&action=verify"
    payload = json.dumps({"tour": tour}).encode()
    req = urllib.request.Request(verify_url, data=payload, headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req).read()
    print(f"Response: {resp.decode()}")
