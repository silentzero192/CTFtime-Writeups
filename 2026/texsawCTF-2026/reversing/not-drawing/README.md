# CTF Writeup

Challenge Name: not drawing  
Platform: texsawCTF 2026  
Category: Reversing  
Difficulty: Easy  
Time spent: ~50 minutes

## 1) Goal (What was the task?)

The challenge gives a single Nintendo Switch homebrew executable, `drawing.nro`, and the goal is to recover a flag in the format `texsaw{...}`.

Success means understanding where the program hides the final output and extracting the exact flag string.

## 2) Key Clues (What mattered?)

- Challenge description: `my drawing broke :(`
- File name and type: `drawing.nro` which is a Nintendo Switch homebrew NRO
- The binary contained embedded OpenGL shader source
- The flag format was known up front: `texsaw{...}`
- The program looked like a drawing app, so visual output mattered more than normal text strings

## 3) Plan (Your first logical approach)

- Identify the file format and inspect the NRO layout to separate code/data from the icon/asset footer.
- Search for strings, shader code, and challenge-specific logic instead of trying to reverse the entire statically linked binary.
- Find where the app uploads vertex data and how it draws the “hidden” output.
- Rebuild that drawing offline and read the flag from the recovered image.

## 4) Steps (Clean execution)

1. I inspected the challenge directory and confirmed there was only one interesting file: `drawing.nro`.

2. I checked the NRO structure with `xxd`, `strings`, and quick header inspection.
   Result: this was a valid Switch homebrew binary with the normal `ASET` footer and an icon JPEG, but no useful RomFS payload.
   Decision: focus on executable logic instead of attached resources.

3. I searched for readable strings and found embedded GLSL shader source around `0x4100c0`.
   Result: the shader was a very simple pass-through vertex/fragment pair that only draws colored geometry.
   Decision: the challenge output was probably stored as geometry rather than as plaintext.

4. I disassembled the early app code around the startup path and followed the OpenGL calls.
   Result: the binary compiles two shaders, links a program, uploads one big vertex buffer, draws it with `glDrawArrays(GL_TRIANGLES, 0, 0xEEE)`, and then clears the screen again.
   Decision: the “drawing broke” idea is the bug itself, so I only needed to recover the uploaded mesh.

5. I located the vertex buffer in `.rodata` at offset `0x44bbe0`.
   Result: it contained `0xEEE` vertices, all white, all at `z = 0`, arranged as small rectangles on a 7-row grid.
   Decision: this was not arbitrary 3D data. It was block text encoded as triangle rectangles.

6. I wrote a solver to parse the mesh as rectangles, convert it into a grid of filled cells, segment each glyph, and map the glyphs back to characters.
   Result: the hidden text decoded cleanly to the final flag.

## 5) Solution Summary (What worked and why?)

The key idea was noticing that the binary was not hiding the flag as a string. Instead, it stored the flag as prebuilt geometry and rendered it with a tiny shader. The program then immediately cleared the screen, so the intended output never stayed visible. By locating the vertex buffer, treating each pair of triangles as one filled block, and decoding the resulting 7-row glyphs, the flag becomes readable without needing a Switch emulator.

## 6) Flag

`texsaw{2switch1918402350923}`

## 7) Lessons Learned (make it reusable)

- In graphics-heavy reversing challenges, always check whether the secret is stored as rendered data instead of plaintext.
- When a binary includes simple shaders, look for the matching vertex buffer and draw call next.
- If the app “draws nothing,” it may still render correctly and then erase its own output.
- You do not always need full decompilation. A focused trace around the rendering path can be enough.

## 8) Personal Cheat Sheet (optional, but very useful)

- `strings -a binary` -> quick way to spot shaders, errors, and app-specific hints
- `xxd -s OFFSET -l SIZE binary` -> inspect headers, tables, and raw asset regions
- Capstone / lightweight disassembly -> useful for tracing a few important functions without opening a full GUI tool
- Pattern to remember: if a challenge mentions drawing, screen, shader, or graphics, check for hidden vertex data, textures, or a render-then-clear bug early

## Reproduction

Run the included solver from the challenge directory:

```bash
python3 solution.py
```

It prints:

```text
texsaw{2switch1918402350923}
```
