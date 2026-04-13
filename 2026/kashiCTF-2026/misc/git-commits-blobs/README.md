# Git, commits, blobs and objects - Writeup

## Challenge

- **Name:** `Git, commits, blobs and objects`
- **Category:** `Misc`
- **Source:** <https://github.com/Aerex0/git-your-works>

## Description

> A lot of work was done and through them a virus made it's way and gitted into the system. Find the flag hidden in the commits. It's a lot for me and i hate git based challenges now. I am now blobed.

---

## TL;DR

The public repository is mostly a distraction:

- more than `1100` commits
- `code.py` changed in tiny synthetic increments
- later `code.py` was deleted
- a `chall.zip` was added at the end

The actual solve is:

1. Clone the repository.
2. Notice the final tree only contains `chall.zip`.
3. Extract `chall.zip`.
4. Realize it contains a `.git/` directory.
5. Run `git fsck --full` on that extracted Git directory.
6. `git fsck` reports a fake object path whose filename is base64.
7. Decode it to get the flag.

---

## 1. Initial Recon

The first thing I wanted was the full history locally, because this challenge name strongly suggests object-database weirdness instead of a normal file-based solve.

### Clone the repository

```bash
git clone --mirror https://github.com/Aerex0/git-your-works repo.git
```

I used a mirror clone so all refs and objects would be available immediately.

### Check the refs and commit count

```bash
git --git-dir=repo.git show-ref
git --git-dir=repo.git rev-list --count --all
git --git-dir=repo.git log --oneline --decorate --all --max-count=20
```

This showed:

- `1104` commits total
- branch tip at `main`
- one PR ref
- the final commits are:
  - `update`
  - `remove code.py`
  - a huge run of numbered commits before that

That already looks suspiciously artificial.

---

## 2. Inspect the Visible History

### What files exist at the tip?

```bash
git --git-dir=repo.git ls-tree -r --name-only main
```

Output:

```text
chall.zip
```

So the visible repository tip only contains one file: `chall.zip`.

### What happened to `code.py`?

```bash
git --git-dir=repo.git log --stat --all -- code.py
```

This showed:

- `code.py` existed through the long numbered history
- it was updated over and over again
- then it was deleted in the final commit

Checking the first and last versions confirms it is mostly noise:

```bash
git --git-dir=repo.git show $(git --git-dir=repo.git log --reverse --format=%H --all -- code.py | sed -n '1p'):code.py
git --git-dir=repo.git show cab52500040429520e94a3ae61cb0a16271fdcf1:code.py
```

Outputs:

```python
x = 0
```

and

```python
x = 1100
```

So the massive commit history is mostly there to bait you into wasting time on trivial sequential edits.

---

## 3. Investigate `chall.zip`

The final commit adds `chall.zip`, so that is the natural pivot point.

### Check what kind of file it is

```bash
git --git-dir=repo.git ls-tree -l main chall.zip
git --git-dir=repo.git show main:chall.zip | xxd -l 64
```

The hex dump starts with `PK`, so it is a ZIP archive as expected.

### List the archive contents

```bash
git --git-dir=repo.git show main:chall.zip > /tmp/git-your-works-chall.zip
unzip -l /tmp/git-your-works-chall.zip | sed -n '1,120p'
```

This is the key observation.

The archive contains an entire Git metadata directory:

```text
.git/
.git/HEAD
.git/index
.git/logs/...
.git/objects/...
```

At this point the challenge becomes much more “Git internals” than “look through commits manually”.

---

## 4. Extract the Embedded Git Repository

Unzip the archive:

```bash
mkdir -p chall
unzip -oq /tmp/git-your-works-chall.zip -d chall
```

Then inspect it:

```bash
find chall/.git -maxdepth 3 | sed -n '1,120p'
git --git-dir=chall/.git show-ref
```

This extracted repository is a stripped-down Git directory with:

- refs
- reflogs
- object files
- branch metadata

The important point is that this is not just a random zip. It is a hand-crafted Git internals puzzle.

---

## 5. Let Git Tell You What Is Broken

This is where `git fsck` becomes the best tool in the room.

Run:

```bash
git --git-dir=chall/.git fsck --full
```

Output:

```text
bad sha1 file: chall/.git/objects/a2/FzaGlDVEZ7bDM0bl9nMTdfMW43M3JuNGw1fQo=
```

This line is the solve.

Why?

Because Git object files are normally stored like this:

```text
.git/objects/aa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

where:

- directory = first 2 hex characters of the object hash
- filename = remaining 38 hex characters

But here the object path is:

```text
.git/objects/a2/FzaGlDVEZ7bDM0bl9nMTdfMW43M3JuNGw1fQo=
```

The filename is clearly **not** a valid SHA-1 suffix. It is base64-looking text instead.

So the challenge author hid data in a deliberately malformed object filename.

---

## 6. Decode the Malformed Object Name

Take the directory prefix `a2` and append the filename:

```text
a2FzaGlDVEZ7bDM0bl9nMTdfMW43M3JuNGw1fQo=
```

Now decode it.

### Using Python

```bash
python3 - <<'PY'
import base64
s = 'a2FzaGlDVEZ7bDM0bl9nMTdfMW43M3JuNGw1fQo='
print(base64.b64decode(s).decode())
PY
```

---

## 7. Why the Commit History Is a Trap

The challenge title and description try to steer you toward:

- commits
- blobs
- objects
- “flag hidden in the commits”

That is not completely false, but the interesting part is not the visible content of all `1100+` commits.

The repo is designed to waste your time in a few ways:

- `code.py` changes in tiny monotonic steps
- the history is intentionally oversized
- the final repo tree hides the useful clue inside an archive
- the archive contains a nested `.git`
- the actual secret is embedded in a malformed object filename, not in normal source code

So the fastest solve path is to stop thinking like a source-code reader and start thinking like a Git plumbing tool.

---

## 8. Minimal Solve Path

If you want the shortest practical route:

```bash
git clone --mirror https://github.com/Aerex0/git-your-works repo.git
git --git-dir=repo.git show main:chall.zip > /tmp/chall.zip
mkdir -p chall
unzip -oq /tmp/chall.zip -d chall
git --git-dir=chall/.git fsck --full
printf 'a2FzaGlDVEZ7bDM0bl9nMTdfMW43M3JuNGw1fQo=' | base64 -d
```

---

## 9. Final Flag

```text
kashiCTF{l34n_g17_1n73rn4l5}
```

---

## 10. Takeaways

- In Git challenges, do not stay at the porcelain layer for too long.
- If a repository suddenly ships a `.zip`, inspect the archive structure before grinding through history.
- `git fsck` is extremely useful for weird-object and corrupted-repo style puzzles.
- A malformed object path is not just an error message in a CTF. It is often the clue itself.

