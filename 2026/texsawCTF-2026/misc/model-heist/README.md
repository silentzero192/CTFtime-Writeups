# CTF Writeup Template (Beginner-Friendly, Portfolio-Ready)

Challenge Name: Model Heist  
Platform: TexSAW CTF 2026  
Category: Reversing  
Difficulty: Easy  
Time spent: ~20 minutes

## 1) Goal (What was the task?)
The challenge gave a single file, `model.h5`, and the description hinted at neural-network layers. The goal was to inspect the model, find the hidden flag, and submit it in the format `texsaw{flag}`.

## 2) Key Clues (What mattered?)
- The only artifact was `model.h5`
- The `.h5` extension strongly suggested an HDF5 / Keras model file
- The description mentioned neural networks and onions/ogres, which hinted at "layers"
- The flag format was provided: `texsaw{flag}`
- Model metadata revealed a suspicious layer named `secret_layer`

## 3) Plan (Your first logical approach)
- Check the file type first to confirm what kind of artifact I was dealing with
- Read any easy metadata or embedded strings before doing deeper analysis
- If the model structure looked interesting, inspect the HDF5 contents directly
- Focus on unusual layer names and try decoding weight values if they looked intentionally crafted

## 4) Steps (Clean execution)
1. **Action:** Ran `file model.h5`  
   **Result:** Confirmed it was an HDF5 file  
   **Decision:** Since HDF5 is commonly used for saved Keras/TensorFlow models, I next looked for readable metadata

2. **Action:** Ran `strings -a -n 6 model.h5`  
   **Result:** Found Keras model configuration, including a layer named `secret_layer` with 26 units  
   **Decision:** A custom-named layer in a CTF is a strong signal, so I focused on inspecting that layer

3. **Action:** Installed `h5py` and used Python to enumerate the HDF5 structure  
   **Result:** Located the dataset `model_weights/secret_layer/sequential/secret_layer/kernel` with shape `(128, 26)`  
   **Decision:** I dumped the values from this kernel to see whether any rows looked hand-crafted instead of normally trained

4. **Action:** Printed the first row of the `secret_layer` kernel  
   **Result:** The row started with values like `0.116`, `0.101`, `0.120`, `0.115`  
   **Decision:** Those numbers looked very close to ASCII codes divided by `1000`, so I tried scaling and decoding them

5. **Action:** Multiplied the first row by `1000`, rounded to integers, and converted them to characters  
   **Result:** The values decoded to `texsaw{w3ight5_t3ll_t4l3s}`  
   **Decision:** That cleanly matched the expected flag format, so the challenge was solved

Important commands/tools used:

```bash
file model.h5
strings -a -n 6 model.h5
python -m pip install --user h5py
```

```python
import h5py, numpy as np

with h5py.File("model.h5", "r") as f:
    kernel = np.array(f["model_weights/secret_layer/sequential/secret_layer/kernel"])
    row0 = np.rint(kernel[0] * 1000).astype(int)
    print("".join(map(chr, row0)))
```

## 5) Solution Summary (What worked and why?)
The key idea was that the model was not just a normal neural network checkpoint. One layer was deliberately named `secret_layer`, and its first row of weights was crafted so that each float represented an ASCII value scaled down by `1000`. Once that row was multiplied by `1000` and converted to characters, it directly revealed the flag. The challenge was really about inspecting model internals rather than using the model for inference.

## 6) Flag
texsaw{w3ight5_t3ll_t4l3s}

## 7) Lessons Learned (make it reusable)
- When a challenge gives you a machine-learning model, inspect the metadata before assuming you need to run the model
- Suspicious layer names like `secret_layer` are often intentional hints
- Numeric model weights can be used as a hiding place for text or flags
- In file-based challenges, `file`, `strings`, and quick structural inspection often solve the problem faster than heavy tooling

## 8) Personal Cheat Sheet (optional, but very useful)
- `file <filename>` -> identify the real file format quickly
- `strings -a -n 6 <filename>` -> pull readable metadata from binary files
- `h5py` -> inspect HDF5 datasets, groups, and attributes
- Pattern to remember: ML model challenge -> check layer names, shapes, biases, and raw weights for hidden messages
