# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

**Challenge Name:** The Gotham Files  
**Platform:** apeorvCTF (-forensic CTF local)  
**Category:** Forensics  
**Difficulty:** Easy  
**Time spent:** ~1 hour

1) **Goal (What was the task?)**  
I was given a PNG titled `challenge.png` and asked to extract the hidden flag in the format `aproovctf{...}`. Success meant producing that exact flag string.

2) **Key Clues (What mattered?)**  
- PNG metadata: artist “The Collector” and comment hinting “only the red light tells the truth.”  
- Image file `challenge.png` with 8-bit palette (palette indexed).  
- Palette entries contained ASCII‑friendly red channel values, suggesting the palette itself carries a message.

3) **Plan (Your first logical approach)**  
- Inspect metadata and image structure (`exiftool`, `pngcheck`) to confirm palette/IDAT info.  
- Visualize the red channel to see if red-only pixels reveal text (thresholding and ASCII art checks).  
- Dump palette values; interpret red channel entries as ASCII characters to recover hidden text.

4) **Steps (Clean execution)**  
1. Ran `exiftool challenge.png` and `pngcheck` to confirm a palette-based PNG and see the “red light truth” hint.  
2. Extracted the red channel as a grayscale image to confirm most data was encoded via red (threshold, mask, ASCII art).  
3. Printed the palette entries and mapped red values to ASCII (selecting values between 32 and 126). The resulting string contained `apoorvctf{th3_c0m1cs_l13_1n_th3_PLTE}` directly.

5) **Solution Summary (What worked and why?)**  
The palette indexes were deliberately constructed so that the red component of each entry corresponded to printable ASCII. By dumping the palette and filtering for printable characters, I read the hidden flag string. The “only the red light tells the truth” hint pointed me toward interpreting the red channel directly, which ultimately revealed the flag.

6) **Flag**  
`aproovctf{th3_c0m1cs_l13_1n_th3_PLTE}`

7) **Lessons Learned (make it reusable)**  
- Always inspect PNG metadata and palette when the file uses indexed color—hidden messages often live in the palette entry bytes.  
- Heed textual hints (“red light tells the truth”) to guide which channel or structure to inspect next.  
- When dealing with binary files that still read as text, filter to printable ASCII rather than dumping everything.

8) **Personal Cheat Sheet (optional, but very useful)**  
- `exiftool challenge.png` → spot metadata hints (Artist/Comment).  
- `pngcheck` → confirm palette and IDAT structure before deeper inspection.  
- Palette red channel → map >32 and <127 to ASCII when hints mention color channels.
