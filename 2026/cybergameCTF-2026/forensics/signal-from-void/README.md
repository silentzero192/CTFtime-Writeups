# Signals From The Void - Writeup

**Challenge Name:** `Signals from the Void`  
**Platform:** `Cybergame CTF 2026`  
**Category:** `Forensics`  
## 1) Goal (What was the task?)

The challenge gave a folder full of noisy PNG images and asked us to find the hidden flag. Success meant recovering the correct flag in the format `SK-CERT{...}`.

## 2) Key Clues (What mattered?)

- The handout contained `256` PNG files with random-looking names.
- Every image was the same format: `800x600`, grayscale, and visually looked like static.
- `exiftool` revealed a custom metadata field called `Pair_index`.
- Each `Pair_index` value appeared exactly twice, which strongly suggested the images had to be processed in pairs.
- Pairwise image comparison revealed hidden text and single-character frames.
- Some recovered character frames had tiny `#N` markers in the top-right corner, which gave the correct order.

## 3) Plan (Your first logical approach)

- First, inspect the files and metadata to see whether the random-looking images had any hidden structure.
- Next, group images by `Pair_index` because the repeated metadata values suggested paired frames.
- Then, compare each pair with simple pixel operations to see if hidden content appears.
- Finally, extract the ordered characters and reconstruct the flag.

## 4) Steps (Clean execution)

1. **Inspect the dataset**
   - I listed the files and checked a few sample images with `file`, `identify`, and `exiftool`.
   - Result: all images were grayscale static, but metadata exposed a `Pair_index` field.
   - Decision: the metadata was the first real lead, so I treated the files as structured pairs instead of independent images.

2. **Confirm the pairing logic**
   - I exported `FileName` and `Pair_index` values and counted them.
   - Result: there were `128` unique indices (`0` to `127`), and each one appeared exactly twice.
   - Decision: compare the two images inside each pair.

3. **Diff each pair**
   - I used a small Python script with PIL/NumPy to load each pair and test pixel-wise comparisons.
   - Result: a pair-difference/equality-style view exposed readable overlays that were invisible in the original noise.
   - Decision: generate recovered images for all `128` pairs and inspect them as a set.

4. **Find the useful recovered frames**
   - I created contact sheets from the recovered outputs.
   - Result: most frames contained telemetry-style text, but `40` of them contained one large character each.
   - Decision: focus on those `40` large-character frames because they looked like a split flag.

5. **Recover the correct order**
   - I noticed a tiny `#N` marker in the top-right of the character frames.
   - Result: the tags ran from `#0` to `#39`, so they gave the exact reading order.
   - Decision: sort the character frames by that number and read the final string directly.

6. **Read and verify the flag**
   - After ordering the characters, the full string became clear.
   - Result: the recovered flag was `SK-CERT{n07h1ng_15_45_17_533m5_1n_5p4c3}`.
   - Decision: double-check ambiguous characters like `_` vs `-` before finalizing.

## 5) Solution Summary (What worked and why?)

The challenge was built around structured image pairing. The images looked like random satellite noise, but the custom `Pair_index` metadata showed they were meant to be compared two at a time. Once I grouped the images into pairs and generated pair-difference views, hidden content appeared. The final flag was not stored in one image; it was split across many recovered character frames, and the tiny `#N` markers told me exactly how to reassemble them.

## 6) Flag

`SK-CERT{n07h1ng_15_45_17_533m5_1n_5p4c3}`

## 7) Lessons Learned (make it reusable)

- Always check metadata early in forensics challenges, especially when files look random or repetitive.
- If many files share the same size and format, look for grouping or ordering fields before trying advanced stego tricks.
- Simple image operations like equality maps, XOR, or subtraction can reveal hidden overlays surprisingly fast.
- Verify visually similar characters carefully, especially `_` vs `-` and `0` vs `O`.

## 8) Personal Cheat Sheet (optional, but very useful)

- `exiftool -csv -FileName -Pair_index *.png` -> quickly extract pairing metadata from all images.
- `file` / `identify` -> confirm image format, size, and whether the files are uniform.
- `python` + `PIL` + `numpy` -> ideal for quick pairwise image comparisons in forensics challenges.
- `montage` or a contact sheet -> helpful when many recovered frames need to be compared visually.
- Pattern to remember: when a folder contains lots of static-like frames, check whether they form pairs, time slices, or reordered fragments before assuming classic steganography.
