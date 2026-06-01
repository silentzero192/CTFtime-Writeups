# Cash Aid Routing

**Category:** Algorithmic / Optimization  
**Flag:** `SDG{1a92cee1c1983db023583a1f542122ad}`

## Challenge Overview

The depot disburses cash to 25 villages each cycle. We must submit a tour of all 25 villages (starting and returning to the depot) whose total distance is under a published threshold.

The threshold is pegged about 10% above the nearest-neighbour heuristic, so a single greedy pass is sufficient — optimality is not required.

## Given Information

- **API:** `https://hackforachangeruntime.vercel.app/api/cash-aid-routing?seed=<seed>`
- **Seed:** `967d2edbd5e7f3d5a19dee7399662ccb9513df27eeeeec0d637e5e918c00fd1e`
- **Challenge page:** `https://hackforachangeruntime.vercel.app/r/7fa3677f-83a7-4511-8873-3a3b1db41d01/cash-aid-routing?token=<token>`
- **Hints:**
  1. Random orderings sit well above the threshold. A simple heuristic clears it.
  2. Nearest-neighbour from the depot is good enough; you do not need optimal.
  3. Distances are plain Euclidean over the published 2D coordinates.

## Solution

### Step 1: Fetch the Instance Data

```bash
curl "https://hackforachangeruntime.vercel.app/api/cash-aid-routing?seed=967d2edbd5e7f3d5a19dee7399662ccb9513df27eeeeec0d637e5e918c00fd1e&action=instance"
```

This returns a JSON object containing:
- 25 villages (IDs 1–25) with 2D coordinates `(x, y)` and cash demands
- A depot (ID 0) at `(14.98, 15.92)`
- A `max_total_distance` threshold of **443.64**

### Step 2: Implement Nearest-Neighbour Heuristic

The algorithm is straightforward:

1. Start at the depot (node 0).
2. Repeatedly visit the nearest unvisited village.
3. After visiting all 25 villages, return to the depot.

Euclidean distance between two points `(x1, y1)` and `(x2, y2)`:

```
d = sqrt((x1 - x2)² + (y1 - y2)²)
```

### Step 3: Compute the Tour

```python
import math, json, urllib.request

# Fetch data
url = "https://hackforachangeruntime.vercel.app/api/cash-aid-routing?seed=967d2edbd5e7f3d5a19dee7399662ccb9513df27eeeeec0d637e5e918c00fd1e&action=instance"
data = json.loads(urllib.request.urlopen(url).read())
points = {v["id"]: (v["x"], v["y"]) for v in data["villages"]}

def dist(a, b):
    return math.sqrt((a[0]-b[0])**2 + (a[1]-b[1])**2)

# Nearest-neighbour from depot
unvisited = set(range(1, 26))
tour = []
current = 0
while unvisited:
    best = min(unvisited, key=lambda v: dist(points[current], points[v]))
    tour.append(best)
    unvisited.remove(best)
    current = best

# Calculate total distance
total = dist(points[0], points[tour[0]]) + dist(points[tour[-1]], points[0])
for i in range(len(tour)-1):
    total += dist(points[tour[i]], points[tour[i+1]])

print(f"Tour: {tour}")
print(f"Distance: {total:.2f} / {data['max_total_distance']}")
```

**Resulting tour:** `[7, 4, 9, 23, 15, 20, 8, 12, 1, 2, 14, 24, 11, 5, 3, 18, 19, 10, 21, 16, 22, 6, 17, 13, 25]`

**Total distance:** 403.31 — well under the 443.64 threshold.

### Step 4: Submit the Tour

```bash
curl -X POST "https://hackforachangeruntime.vercel.app/api/cash-aid-routing?seed=967d2edbd5e7f3d5a19dee7399662ccb9513df27eeeeec0d637e5e918c00fd1e&action=verify" \
  -H "Content-Type: application/json" \
  -d '{"tour":[7,4,9,23,15,20,8,12,1,2,14,24,11,5,3,18,19,10,21,16,22,6,17,13,25]}'
```

**Response:**

```json
{
  "ok": true,
  "total_distance": 403.31,
  "max_total_distance": 443.64,
  "passed": true,
  "dispatch_token": "d60c1c2132dbf532e50af8699a6aea82",
  "note": "Submit dispatch_token as proof to claim-runtime-flag."
}
```

### Step 5: Claim the Flag

Enter the dispatch token `d60c1c2132dbf532e50af8699a6aea82` into the "Claim Flag" button on the challenge page.

**Flag:** `SDG{1a92cee1c1983db023583a1f542122ad}`

## Key Takeaways

- This is a classic **Travelling Salesman Problem (TSP)** variant but with a forgiving threshold (~10% above nearest-neighbour).
- No optimization beyond a simple greedy nearest-neighbour was necessary — the threshold was deliberately set to be easily achievable.
- The API design is clean: `/api/cash-aid-routing?action=instance` to get data, `/api/cash-aid-routing?action=verify` to submit, and the returned `dispatch_token` acts as a proof-of-solution.

## Files

- `solve.py` — Python script implementing the nearest-neighbour solution
