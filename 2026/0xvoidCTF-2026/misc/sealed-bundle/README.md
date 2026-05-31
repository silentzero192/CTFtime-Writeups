# Sealed Bundle - Misc Writeup

## Challenge Information

- **Name:** `Sealed Bundle`  
- **Category:** `Misc`  

---

## Initial Analysis

The challenge directory contains:

```
misc/
├── 02_easy_hidden_archive.zip
└── sealed-bundle/
    ├── readme.txt
    └── notes/
        └── .keep
```

The `sealed-bundle/` directory has been extracted from a ZIP archive. It contains:

| File | Size | Content |
|------|------|---------|
| `readme.txt` | 56 bytes | `List every file in the archive, including hidden names.` |
| `notes/.keep` | 20 bytes | `notes folder marker` |

The hint is clear: **"List every file in the archive, including hidden names."** — but there are no visible hidden files in the extracted directory. The key must lie in the archive itself.

---

## Step 1: Inspect the Provided ZIP

The original artifact is `02_easy_hidden_archive.zip`. Let's list its contents without extracting:

```bash
$ unzip -l 02_easy_hidden_archive.zip
Archive:  02_easy_hidden_archive.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      426  2026-05-17 12:01   bundle.zip
---------                     -------
      426                     1 file
```

This is a **nested archive** — the outer ZIP contains a single file: `bundle.zip`.

---

## Step 2: Inspect the Inner ZIP

Extract the outer archive, then inspect the inner `bundle.zip`:

```bash
$ unzip 02_easy_hidden_archive.zip
Archive:  02_easy_hidden_archive.zip
  inflating: bundle.zip

$ unzip -l bundle.zip
Archive:  bundle.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       56  2026-05-17 12:01   readme.txt
       20  2026-05-17 12:01   notes/.keep
       37  2026-05-17 12:01   .answer.txt
---------                     -------
      113                     3 files
```

There it is — the inner `bundle.zip` contains **three files**, not two:

| File | Hidden? | Content |
|------|---------|---------|
| `readme.txt` | No | The hint |
| `notes/.keep` | Partially | A folder marker (hidden via `.` in parent) |
| **`.answer.txt`** | **Yes** | **The flag** |

The `.answer.txt` file starts with a dot, making it a **hidden file** on Unix-like systems. It was silently present in the archive all along.

---

## Step 3: Extract and Read the Hidden File

```bash
$ unzip -o bundle.zip
Archive:  bundle.zip
  inflating: readme.txt
  inflating: notes/.keep
  inflating: .answer.txt

$ cat .answer.txt
0xV01D{HIDDEN_FILES_ARE_STILL_FILES}
```

---

## The Flag

```
0xV01D{HIDDEN_FILES_ARE_STILL_FILES}
```

---

## Key Takeaways

1. **Always list archive contents before extracting.** Tools like `unzip -l` or `tar -tvf` show every entry including hidden files (those starting with `.`), regardless of how the extraction process handles them.

2. **Nested archives are a common CTF trope.** A ZIP inside a ZIP, or a TAR inside a GZIP — each layer is designed to obscure the real payload behind an extra step.

3. **The hint was literal.** *"List every file in the archive, including hidden names"* was not metaphorical — it was telling you exactly what command to run. `unzip -l bundle.zip` would have revealed `.answer.txt` immediately without needing to extract anything.

4. **Hidden files are still files.** On Unix-like systems, files starting with `.` are only hidden from default `ls` output. Archive tools and filesystem listings always expose them.
