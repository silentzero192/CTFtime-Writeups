# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

Challenge Name: Palo Arto  
Platform: VolgaCTF Qualifier 2026  
Category: Forensics / Stego  
Difficulty: Easy  
Time spent: ~25 minutes

## 1) Goal (What was the task?)

The challenge asked us to find a hidden message inside an artwork-related file served by the challenge website. Success meant recovering a flag in the format `VolgaCTF{...}`.

## 2) Key Clues (What mattered?)

- Description: "Sometimes artists include hidden messages in their work."
- The challenge page used an inline `data:image/png;base64,...` image instead of a normal image file path.
- The extracted file was a palette-based PNG (`1000x622`, 8-bit colormap).
- `pngcheck`, `exiftool`, and `binwalk` showed a clean PNG with no obvious appended archive or custom chunk.
- The palette looked suspicious: all `256` palette entries were arranged in near-identical pairs that differed by only `1` bit in the blue channel.

## 3) Plan (Your first logical approach)

- Fetch the page and extract the real challenge image from the inline base64 data.
- Check the PNG structure first to rule out easy wins like hidden metadata or appended files.
- If the file structure looked clean, inspect the palette and pixel indices because indexed PNGs are a common stego format.
- Try rebuilding a hidden bitstream from the palette choice made for each pixel.

## 4) Steps (Clean execution)

1. I downloaded the challenge page and saved the HTML.
   Result: the main image was embedded directly in the page as a base64 PNG.
   Decision: extract that PNG and analyze it as the real challenge artifact.

2. I decoded the inline base64 image into `header.png`.
   Result: the file was a palette PNG, not a normal RGB image.
   Decision: check whether the secret was stored in chunks, metadata, or the palette/index data.

3. I ran lightweight file checks with `pngcheck`, `exiftool`, and `binwalk`.
   Result: the PNG only had normal chunks like `IHDR`, `PLTE`, `IDAT`, and `IEND`, with no appended ZIP or text payload.
   Decision: focus on the indexed color data instead of chunk-level hiding.

4. I inspected the PNG palette.
   Result: every palette entry had a twin color that differed by exactly `1` in the blue channel, which is a strong stego pattern.
   Decision: treat each pixel's palette choice as a hidden bit.

5. I read every pixel index from the PNG and took `index & 1`.
   Result: packing those bits row-major, `MSB` first, immediately produced readable bytes.
   Decision: search the recovered byte stream for the expected `VolgaCTF{...}` pattern.

6. The recovered payload started with the flag at byte offset `0`.
   Result: the flag was extracted cleanly without needing decompression or extra decoding.
   Decision: automate the method in `solve.py`.

Example command:

```bash
python3 solve.py header.png
```

## 5) Solution Summary (What worked and why?)

The important pattern was the indexed PNG palette. The image was built so that palette colors came in visually identical pairs, letting the author choose one twin or the other without changing how the image looked to the eye. That choice encoded a hidden bit in the parity of the palette index. Once those bits were read in normal row-major order and packed `MSB` first, the payload started with the flag text.

## 6) Flag

`VolgaCTF{7h3r3_15_n0_m34n1ngfu1_m3ss4g3_h3r3}`

## 7) Lessons Learned (make it reusable)

- Indexed PNGs are worth checking separately from normal RGB images because the palette itself can carry data.
- If a PNG looks structurally clean, the hiding place may be in pixel selection rather than metadata or appended files.
- Near-duplicate palette entries are a major clue for stego in palette images.
- When testing bitstreams, try simple packings first: row-major order and `MSB`-first byte packing.

## 8) Personal Cheat Sheet (optional, but very useful)

- `pngcheck -v file.png` -> inspect PNG chunks and confirm whether the structure is ordinary.
- `exiftool file.png` -> quickly rule out easy metadata-based hiding.
- `binwalk file.png` -> check for appended archives or embedded file signatures.
- Palette PNG pattern -> if many palette entries are near-duplicates, check whether pixel index choice stores bits.
- Web challenge pattern -> always inspect page source when an image is embedded with `data:image/...`.
