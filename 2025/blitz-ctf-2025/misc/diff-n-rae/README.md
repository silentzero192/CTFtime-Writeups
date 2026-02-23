# CTF Writeup

**Challenge Name:** Diff'n Rae  
**Platform:** Blitz CTF 2025  
**Category:** Misc  
**Difficulty:** Easy  
**Time Spent:** ~20 minutes  

---

## 1) Goal (What was the task?)

The challenge description hinted:

> I love to use GitHub especially because of the compare feature.

We were given two image files and needed to recover hidden information.  
The goal was to extract the hidden data and retrieve the flag in the format:

```
Blitz{...}
```

---

## 2) Key Clues (What mattered?)

- Challenge name: **Diff'n Rae** → strongly hints toward `diff`
- Description mentions:
  - GitHub compare feature
- Two image files:
  ```
  img1.jpg
  img2.jpg
  ```
- “Compare feature” → suggests checking differences between files
- Some writeups used XOR (conceptually similar: comparing differences)

---

## 3) Plan (Your first logical approach)

- Compare both images to identify differences.
- Since they are binary files, extract readable strings first.
- Use `diff` to compare string outputs.
- Reconstruct meaningful hidden data from the differences.
- Decode the reconstructed payload.

---

## 4) Steps (Clean execution)

### Step 1: Extract Strings from Both Images

```bash
strings -n 1 img1.jpg > 1.txt
strings -n 1 img2.jpg > 2.txt
```

- `-n 1` ensures even single-character strings are extracted.
- This helps catch small hidden fragments.

---

### Step 2: Compare the Extracted Strings

```bash
diff 1.txt 2.txt
```

Output:

```
3d2
< Qmx
8c7
< )
---
> pdHp7)
10c9
< ZDFm
---
> Rl8x
77d75
< U1
949a948
>       91N
4707d4705
< TNm
4770a4769
> dUx9
```

These fragments represent pieces of hidden Base64 data.

---

### Step 3: Reconstruct the Base64 Payload

By carefully combining the differing fragments in correct order, we get:

```
QmxpdHp7ZDFmRl8xU191NTNmdUx9
```

---

### Step 4: Decode Base64

```bash
echo "QmxpdHp7ZDFmRl8xU191NTNmdUx9" | base64 -d
```

Output:

```
Blitz{d1fF_1S_u53fuL}
```

---

## 5) Solution Summary (What worked and why?)

The challenge relied on the concept of file comparison.

Key idea:
- Two similar image files contained slight differences.
- Extracting strings allowed us to view readable embedded fragments.
- Using `diff` revealed hidden Base64 segments.
- Reconstructing and decoding the Base64 string revealed the flag.

This mimics GitHub's “compare” feature — highlighting differences between files.

---

## 6) Flag

```
Blitz{d1fF_1S_u53fuL}
```

---

## 7) Lessons Learned

- When given two similar files, always compare them.
- `diff` is extremely powerful in CTFs.
- Extract strings from binary files before comparing.
- Base64 fragments often appear in steganography challenges.
- The challenge name often directly hints at the intended technique.

---

## 8) Personal Cheat Sheet

- `strings -n 1 file` → Extract all readable characters  
- `diff file1 file2` → Compare differences  
- `echo STRING | base64 -d` → Decode Base64  
- If two files look similar → Always compare them  
- GitHub compare → Think `diff` immediately  
