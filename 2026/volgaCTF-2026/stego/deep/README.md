Challenge Name: deep
Platform: VolgaCTF-2026
Category: Forensics / Steganography
Difficulty: Medium
Time spent: ~1 hour

## 1) Goal (What was the task?)
We were given a stego challenge named `deep` with a challenge image `stego.png`, a model checkpoint directory `encoder/`, and two Python files: `steganogan.py` and `train.py`. The objective was to recover the hidden message and extract the flag in the format `VolgaCTF{...}`.

Success meant finding a valid flag string, not just identifying that the image used steganography.

## 2) Key Clues (What mattered?)
- The challenge name was `deep`, which strongly hinted at a deep learning based hiding method rather than simple LSB.
- The file `steganogan.py` referenced **SteganoGAN**, which is a neural-network-based image steganography method.
- The script implemented both `DenseEncoder` and `DenseDecoder`, but the provided files only included an `encoder/` checkpoint and no obvious `decoder.pt`.
- The `decode()` function in `steganogan.py` used Reed-Solomon via `RSCodec`, which meant the hidden message had error correction and was probably repeated many times across the image.
- The image `stego.png` was large: `2040 x 1356`, which gives a very large payload capacity for a neural steganography model.
- The `make_payload()` function repeated the encoded message until it filled the whole image. That repetition became the key to recovering the flag even with some decoding noise.

## 3) Plan (Your first logical approach)
- First, inspect the provided files to understand whether this was a simple image stego problem or a model-based one.
- Next, read `steganogan.py` and `train.py` to understand exactly how the payload was embedded and extracted.
- Then, check whether the flag might be hiding in easy places first: PNG metadata, raw bit planes, strings inside the model files, or obvious plaintext artifacts.
- After ruling those out, switch to the real attack path: rebuild the provided encoder checkpoint, generate synthetic training data from it, learn a compatible decoder, and then recover the repeated payload from the real image.

## 4) Steps (Clean execution)

### 1. Enumerated the challenge files
**Action:** Listed the files in the challenge directory.

**Result:** Found:
- `stego.png`
- `steganogan.py`
- `train.py`
- `requirements.txt`
- `encoder/` directory with serialized model data

**Decision:** This immediately suggested the challenge was not plain LSB or metadata stego. The presence of SteganoGAN code and a model checkpoint meant the hidden message was probably embedded through a learned neural encoder.

### 2. Read the extraction logic in `steganogan.py`
**Action:** Opened `steganogan.py` and focused on:
- `DenseEncoder`
- `DenseDecoder`
- `make_payload()`
- `decode()`

**Result:** The important behavior was:
- The message is encoded with Reed-Solomon.
- The encoded bits are followed by a `32-bit` zero marker.
- That full bit sequence is **repeated** until it fills the image.
- During extraction, the decoder predicts one bit per pixel, the script packs bits into bytes, splits on the zero marker, and tries Reed-Solomon decoding on the fragments.

**Decision:** This told me two very important things:
- The image itself really contains a long repeated bitstream.
- I did not necessarily need a perfect decoder. If I could recover the hidden bits with good enough accuracy, I could use repetition and Reed-Solomon to reconstruct the real message.

### 3. Verified that simple stego methods were not enough
**Action:** Checked the PNG structure, metadata, raw strings, and low bit planes.

**Result:**
- No useful metadata was present.
- No appended ZIP or obvious extra PNG chunks were present.
- Simple plaintext extraction from raw pixel bit planes did not reveal the flag.
- Direct string searches through the checkpoint data also did not reveal the flag.

**Decision:** This ruled out the usual beginner shortcuts. The challenge really needed the model logic.

### 4. Understood the checkpoint problem
**Action:** Investigated the `encoder/` directory contents.

**Result:** It was not a single `encoder.pt` file. Instead, it was an unpacked PyTorch archive with:
- `data.pkl`
- `byteorder`
- `version`
- `data/*`

**Decision:** Since `torch.load('encoder')` fails on a directory, I repacked the directory contents into a standard zip-style PyTorch checkpoint so it could be loaded normally.

### 5. Loaded the encoder model
**Action:** Installed the required Python dependencies and loaded the checkpoint into the `DenseEncoder` class from `steganogan.py`.

**Result:** The model loaded cleanly with the expected architecture:
- `data_depth = 1`
- `hidden_size = 32`

**Decision:** At this point I had a working stego encoder, but still no provided decoder. That meant I needed to create my own extraction path.

### 6. Used the encoder as a data generator
**Action:** Built synthetic training samples using the real encoder:
- Sampled image crops from `stego.png` as natural-looking cover images
- Generated random payload bits
- Ran the encoder to produce synthetic stego crops
- Used those `(stego_crop -> payload_bits)` pairs as supervised training data

**Result:** I could generate as much labeled training data as I wanted, even though the original hidden message was unknown.

**Decision:** This turns the problem into a learning problem: if I can train a decoder on synthetic examples from the same encoder, it should generalize well enough to the real challenge image.

### 7. Trained a compatible decoder
**Action:** Trained a new `DenseDecoder(1, 32)` model against the encoder-generated samples using binary cross-entropy loss.

**Result:** The trained decoder reached about `93-95%` bit accuracy on held-out synthetic patches, which is strong enough when the true payload is repeated many times and protected by Reed-Solomon.

**Decision:** A decoder at this accuracy does not need to be perfect. Because the payload repeats across the whole image, I could do majority voting across repeats to denoise the bitstream.

### 8. Ran the trained decoder over the real image
**Action:** Applied the learned decoder to `stego.png` tile by tile and collected one predicted bit per pixel.

**Result:** This produced a noisy but highly confident bitstream for the entire image.

**Decision:** Now the remaining problem was not model inference, but message reconstruction.

### 9. Recovered the repeated payload
**Action:** Used the behavior from `make_payload()`:
- For a candidate flag length, compute the Reed-Solomon encoded length
- Convert that to total payload length in bits
- Include the extra `32-bit` zero marker
- Split the full image bitstream into repeated chunks of that size
- Majority-vote each bit position across all repetitions

**Result:** This dramatically reduces random bit errors, because the same hidden message is embedded over and over again.

**Decision:** After majority voting, the payload becomes stable enough for Reed-Solomon decoding.

### 10. Brute-forced plausible message lengths and Reed-Solomon-decoded the result
**Action:** Tried reasonable plaintext lengths, reconstructed the repeated payload for each one, then passed the candidate bytes through `RSCodec.decode()`.

**Result:** At message length `43`, the decode succeeded and returned:

`VolgaCTF{Th1s_m3ss@ge_wa$_d3eeply_embedded}`

**Decision:** This matched the required flag format exactly, so the challenge was solved.

## 5) Solution Summary (What worked and why?)
The core idea was recognizing that this was not ordinary steganography, but **model-based steganography using SteganoGAN**. The challenge gave us the encoder checkpoint but not the decoder checkpoint, so instead of trying random image tricks forever, I used the encoder itself to generate labeled synthetic stego data. That allowed me to train a fresh decoder compatible with the provided model.

Once I had a decoder with good bit accuracy, the rest of the solve came from reading the code carefully: the payload was Reed-Solomon encoded, terminated with 32 zero bits, and then repeated until the whole image was full. That repetition let me majority-vote the recovered bits across many copies of the same message, which cleaned up decoding errors. After that, Reed-Solomon successfully recovered the original flag.

## 6) Flag
`VolgaCTF{Th1s_m3ss@ge_wa$_d3eeply_embedded}`

## 7) Lessons Learned (make it reusable)
- If a stego challenge ships a neural model or training code, assume the intended path may involve understanding the model rather than only using classic tools like `zsteg` or `binwalk`.
- Read helper functions carefully. In this challenge, `make_payload()` revealed the most important fact: the message was repeated across the entire image.
- Reed-Solomon is a major clue that the author expected some decoding noise. That usually means an approximate recovery method can still work.
- If a decoder is missing but an encoder is present, the encoder can often be turned into a training-data generator for a surrogate decoder.

## 8) Personal Cheat Sheet (optional, but very useful)
- `file <target>` -> quickly identify image type, serialized data, or unexpected file format clues.
- `strings -a <file>` -> useful for quick wins, but not enough for learned stego challenges.
- Read the embedding code before trying random extraction techniques.
- Pattern: if the code repeats the payload, use majority voting across repetitions to fix bit errors.
- Pattern: if the challenge uses error-correcting codes like Reed-Solomon, even noisy extraction may still be enough.
- Pattern: if only the encoder is provided, generate synthetic labeled pairs and train your own decoder.
