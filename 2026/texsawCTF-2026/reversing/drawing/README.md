# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

**Challenge Name:** drawing  
**Platform:** TexSAW CTF 2026  
**Category:** Reversing  
**Difficulty:** Easy  
**Time spent:** ~30 minutes

## 1) Goal (What was the task?)
The challenge gave a single binary named `drawing.nro` and the description `drawing be like`. The goal was to recover the flag in the format `texsaw{...}` by reverse engineering how the program worked and identifying where the hidden output was stored.

Success meant extracting the exact flag string from the binary, not just understanding the file format.

## 2) Key Clues (What mattered?)
- The challenge name was `drawing`
- The only file was `drawing.nro`
- The extension `.nro` strongly suggested a Nintendo Switch homebrew executable
- `strings` showed OpenGL / graphics-related symbols and tiny GLSL shaders
- There was no obvious plaintext flag in the binary
- The description hinted that the answer might be hidden in something the program *draws*, not something it prints

## 3) Plan (Your first logical approach)
- First, identify the file type and confirm what kind of binary I was dealing with.
- Next, check for easy wins such as embedded strings, shader source, or obvious flag text.
- After that, inspect the rendering code to see what data gets sent to OpenGL.
- If the binary was drawing shapes manually, reconstruct the geometry and render it offline to reveal the hidden message.

## 4) Steps (Clean execution)

### 1. Inspect the challenge file
I started by listing the files and checking the binary:

```bash
ls -la
file drawing.nro
strings -a -n 6 drawing.nro | sed -n '1,220p'
```

### Result
- There was only one file: `drawing.nro`
- `file` did not identify it cleanly and only reported `data`
- The binary started with `HOMEBREWNRO0`, which confirmed it was a Switch homebrew NRO
- `strings` showed lots of OpenGL symbols plus two short GLSL shaders

### Decision
The lack of a plaintext flag suggested this was not a simple `strings` challenge. The presence of shaders and many GL functions strongly suggested the flag was being rendered visually.

---

### 2. Parse the NRO structure manually
Since normal ELF tools were not especially helpful on the raw NRO file, I inspected the header manually with `xxd` and a short Python parser.

Useful observations from the header:
- `.text` region size: `0x40f000`
- `.rodata` begins around: `0x40f000`
- `.data` begins around: `0x563000`

This gave me the rough memory layout needed for disassembly and data inspection.

### Result
I confirmed the binary had the usual code / rodata / data split, even if it was not packaged like a normal ELF on disk.

### Decision
Once I knew where `.rodata` lived, I could follow references to shader strings and rendering data.

---

### 3. Find the rendering setup
I used AArch64 disassembly and a bit of manual tracing to inspect the real application code inside the NRO. The important function was the one that:

- loaded the embedded vertex shader and fragment shader
- uploaded a large vertex buffer
- configured vertex attributes
- called `glDrawArrays`

Key instructions in that function:

- Shader sources loaded from `.rodata`:
  - `0xe5c: adrp x1, #0x410000`
  - `0xe60: add x1, x1, #0xc0`
  - `0xe78: adrp x1, #0x410000`
  - `0xe7c: add x1, x1, #0x1a0`

- Vertex buffer upload:
  - `0xfb8: adrp x2, #0x44b000`
  - `0xfbc: add x2, x2, #0xbe0`
  - `0xfc0: mov x1, #0x137a0`

- Vertex layout:
  - stride `0x18` bytes
  - attribute 0 at offset `0x0`
  - attribute 1 at offset `0xc`

- Draw call:
  - `0x10ec: mov w1, #0`
  - `0x10f0: mov w2, #0xcfc`
  - `0x10f4: mov w0, #4`

### Result
This told me exactly what the geometry looked like:
- `glBufferData(..., size=0x137a0, data=0x44bbe0, ...)`
- vertices are 24 bytes each
- layout is `vec3 position + vec3 color`
- draw mode `4` is `GL_TRIANGLES`
- vertex count `0xcfc` = `3324`

### Decision
At this point, the fastest path was not full emulation. It was to extract the vertex buffer directly and render it offline.

---

### 4. Extract and analyze the vertex data
I wrote a small Python script to read the data at offset `0x44bbe0` and decode it as floats:

```python
import struct

OFF = 0x44bbe0
SIZE = 0x137a0

with open("drawing.nro", "rb") as f:
    f.seek(OFF)
    data = f.read(SIZE)

vals = struct.unpack("<" + "f" * (SIZE // 4), data)
verts = [vals[i:i+6] for i in range(0, len(vals), 6)]
print(len(verts))
print(verts[:3])
```

### Result
- There were `3324` vertices, matching the draw call
- All color values were white: `(1.0, 1.0, 1.0)`
- The coordinates were tightly packed and aligned like a block grid

That was the big hint: the binary was not drawing a 3D object or animation. It was drawing a bunch of tiny white rectangles that likely formed letters.

### Decision
Render the triangles to an image and read the text.

---

### 5. Reconstruct the drawing
I used Pillow to map the normalized X/Y coordinates onto a 2D image and draw every triangle:

```python
from PIL import Image, ImageDraw
import struct

OFF = 0x44bbe0
SIZE = 0x137a0
W, H = 2200, 300
PAD = 20

with open("drawing.nro", "rb") as f:
    f.seek(OFF)
    data = f.read(SIZE)

vals = struct.unpack("<" + "f" * (SIZE // 4), data)
verts = [vals[i:i+6] for i in range(0, len(vals), 6)]
xs = [v[0] for v in verts]
ys = [v[1] for v in verts]
minx, maxx = min(xs), max(xs)
miny, maxy = min(ys), max(ys)

img = Image.new("RGB", (W, H), "black")
draw = ImageDraw.Draw(img)

def mappt(x, y):
    px = PAD + (x - minx) / (maxx - minx) * (W - 2 * PAD)
    py = H - (PAD + (y - miny) / (maxy - miny) * (H - 2 * PAD))
    return (px, py)

for i in range(0, len(verts), 3):
    tri = verts[i:i+3]
    pts = [mappt(v[0], v[1]) for v in tri]
    draw.polygon(pts, fill=(255, 255, 255))

img.save("/tmp/drawing_render.png")
```

### Result
The rendered image clearly showed a blocky sentence made from white square segments. By reading the generated picture, the hidden flag text was visible.

### Decision
Manually transcribe the flag from the rendered image.

## 5) Solution Summary (What worked and why?)
The core idea was that the flag was not stored as a normal string. Instead, the binary contained raw geometry data that OpenGL used to draw the flag on screen. By tracing the graphics setup, I found the exact vertex buffer address and size, extracted the triangles, and re-rendered them outside the game. That converted the “drawing” back into readable text and revealed the flag.

This is a great example of a reversing challenge where the answer lives in assets or render data rather than in obvious string constants.

## 6) Flag
`texsaw{switch96959d49370}`

## 7) Lessons Learned (make it reusable)
- When a reversing challenge mentions drawing, graphics, shaders, or rendering, check whether the flag is visual instead of textual.
- If `strings` fails, look for how the program builds or displays data, not just what it stores directly.
- For Switch homebrew binaries, manual header inspection can still give enough structure to reverse important code paths.
- Graphics pipelines often reveal useful constants such as buffer sizes, vertex layouts, and draw counts that make offline reconstruction possible.

## 8) Personal Cheat Sheet (optional, but very useful)
- `strings -a -n 6 file` -> quick scan for titles, shaders, messages, and imported function names
- `xxd file | head` -> useful for spotting custom headers and magic values
- `glBufferData` arguments -> check where vertex or texture data comes from
- `glVertexAttribPointer` -> tells you how to parse each vertex
- `glDrawArrays` / `glDrawElements` -> tells you how much geometry is actually used
- Pattern to remember: if all geometry is simple white rectangles on a regular grid, it may be custom pixel-font text encoded as triangles
