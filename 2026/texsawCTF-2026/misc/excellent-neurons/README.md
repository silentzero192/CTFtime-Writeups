# CTF Writeup

Challenge Name: Excellent Neurons  
Platform: texsawCTF 2026  
Category: Reversing / Misc  
Difficulty: Medium  
Time spent: ~25 minutes

## 1) Goal (What was the task?)

The challenge gave me an Excel workbook and said the flag could be found by reverse engineering a neural network stored inside it. Success meant recovering a valid flag in the format `texsaw{...}` and confirming the workbook would evaluate it as `FLAG`.

## 2) Key Clues (What mattered?)

- The only file was `challenge.xlsx`, which means the real content could be inspected as zipped XML.
- The workbook had two sheets: `Challenge` and `Network`.
- `sharedStrings.xml` described the architecture clearly: `Input(30) -> ReLU -> Hidden1(60) -> ReLU -> Hidden2(1) -> ReLU -> Output(4) -> Sigmoid`.
- The input was normalized as `ASCII / 127`.
- The output rule was explicit: `(F>0.5, L<0.5, A>0.5, G<0.5) -> FLAG`.
- The first layer weights were very sparse and mostly `-1`, `0`, or `1`, which strongly suggested per-character boundary checks instead of a complex learned model.

## 3) Plan (Your first logical approach)

- Inspect the `.xlsx` as a ZIP archive to read the raw workbook XML instead of relying on Excel manually.
- Find the important formulas, labels, and sheet layout to understand how the network was wired.
- Extract the first-layer weights and biases to see whether each neuron represented a simple condition on one input character.
- Convert those conditions back into ASCII values, rebuild the candidate flag, and verify it with a forward pass.

## 4) Steps (Clean execution)

1. I listed the workbook contents with `unzip -l challenge.xlsx`.
   Result: the interesting files were `xl/workbook.xml`, `xl/sharedStrings.xml`, `xl/worksheets/sheet1.xml`, and `xl/worksheets/sheet2.xml`.
   Decision: inspect the shared strings and worksheet XML to understand the labels and formulas.

2. I read `xl/sharedStrings.xml` and `xl/workbook.xml`.
   Result: the workbook confirmed the two-sheet layout and described the neural-network architecture, normalization rule, and final success condition.
   Decision: move to `sheet2.xml`, because that sheet held the actual weights and formulas.

3. I inspected `xl/worksheets/sheet2.xml`.
   Result: rows `11` to `70` held the first-layer weights, row `75` held the first-layer biases, row `87` held the second-layer weights, row `92` held the second-layer bias, and rows `101` to `110` handled the final output layer.
   Decision: extract the first layer programmatically because reading it manually would be slow and error-prone.

4. I parsed the XML with a short Python script.
   Result: every first-layer neuron depended on exactly one input position, and each weight was either `+1` or `-1`.
   Decision: treat each pair of neurons as lower-bound and upper-bound checks for a single normalized ASCII value.

5. I converted the first-layer equations into constraints.
   Result: for each position, the workbook encoded a very tight interval around one character:
   - `x + bias` with weight `+1` gave an upper-bound style check.
   - `-x + bias` with weight `-1` gave a lower-bound style check.
   Multiplying the normalized value by `127` recovered the exact ASCII character.
   Decision: decode all 30 positions and trim the trailing null positions.

6. The recovered characters spelled:
   Result: `texsaw{n3ur4l_r3v3rs3}` followed by unused zero-valued positions.
   Decision: keep the flag text and leave the extra input cells blank, since blank cells evaluate to `0` in the workbook.

7. I ran a final forward-pass verification.
   Result: the recovered string produced output values satisfying `(F>0.5, L<0.5, A>0.5, G<0.5)`, so the workbook would display `FLAG`.
   Decision: finalize the solve.

## 5) Solution Summary (What worked and why?)

The key idea was realizing this was not a "mysterious black-box AI" problem. The first hidden layer was actually a collection of simple threshold checks, one character position at a time. Because the input was `ASCII / 127`, each pair of neurons effectively boxed one input into a tiny interval that matched a single ASCII character. Once those bounds were converted back to characters, the flag appeared directly. The later layers only acted as a scoring and verification mechanism, so the real solve was reversing the first-layer constraints.

## 6) Flag

`texsaw{n3ur4l_r3v3rs3}`

## 7) Lessons Learned (make it reusable)

- An `.xlsx` file is just a ZIP archive, so checking its XML internals is often faster than using the spreadsheet UI.
- If a "neural network" has sparse integer-like weights, it may really be encoding logic checks rather than a complex model.
- When inputs are normalized, always convert back to the original scale before guessing meaning.
- If a challenge gives explicit output conditions, use them to verify your recovered input instead of stopping at a guess.

## 8) Personal Cheat Sheet (optional, but very useful)

- `unzip -l file.xlsx` -> list workbook internals quickly.
- `unzip -p file.xlsx path/in/archive.xml` -> print specific XML files without extracting everything.
- `sharedStrings.xml` -> maps string indexes to human-readable sheet labels.
- `sheet*.xml` -> contains the actual cell formulas, values, and structure.
- Pattern: sparse `-1/0/1` weights in a network often mean comparisons, gates, or threshold logic.
- Pattern: if a spreadsheet uses `IF(cell=\"\",0,...)`, blank cells may be part of the intended solution.
