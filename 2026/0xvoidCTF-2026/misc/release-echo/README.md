# Release Echo - Misc Writeup

## Challenge Information

- **Name:** `Release Echo`  
- **Category:** `Misc`  

---

## Initial Analysis

The challenge provides a single ZIP file containing what appears to be a `git` repository:

```
release-echo/
└── 07_hard_git_fossil.zip
```

Extracting and inspecting the archive:

```bash
$ unzip -l 07_hard_git_fossil.zip
Archive:  07_hard_git_fossil.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       54  2026-05-17 12:01   repo/daily_note.txt
       63  2026-05-17 12:01   repo/README.md
        ...
      217  2026-05-17 12:01   repo/.git/index
        ...
       23  2026-05-17 12:01   repo/.git/HEAD
       41  2026-05-17 12:01   repo/.git/refs/heads/master
      ...
```

The ZIP contains a `repo/` directory with a full `.git` folder — this is a git repository archive.

---

## Step 1: Extract and Inspect the Repository

```bash
$ unzip 07_hard_git_fossil.zip
$ cd repo/
```

The working tree contains two files:

```bash
$ ls -la
total 16
drwxrwxr-x 3 jilani jilani 4096 May 18 11:20 .
drwxrwxr-x 2 jilani jilani 4096 May 18 11:20 ..
drwxrwxr-x 7 jilani jilani 4096 May 18 11:20 .git
-rw-rw-rw- 1 jilani jilani   63 May 17 12:01 README.md
-rw-rw-rw- 1 jilani jilani   54 May 17 12:01 daily_note.txt
```

```bash
$ cat README.md
Old notes were cleaned up before release. Check what changed.

$ cat daily_note.txt
release note
sensitive note removed before shipping
```

The `README.md` tells us: *"Old notes were cleaned up before release. Check what changed."* — this points directly to the git commit history.

---

## Step 2: Inspect the Git Log

```bash
$ git log --oneline
e067b54 (HEAD -> master) clean release notes
1d8be50 add first draft notes
```

Two commits:
1. `1d8be50` — **"add first draft notes"** (initial commit)
2. `e067b54` — **"clean release notes"** (HEAD)

---

## Step 3: Examine the Commit Diff

### Latest Commit (HEAD)

```bash
$ git show e067b54
commit e067b5405116bcca6ea1c69618605b75c43985ac
Author: CTF Builder <ctf@example.local>
Date:   Sun May 17 12:01:52 2026 +0300

    clean release notes

diff --git a/daily_note.txt b/daily_note.txt
index 58207f1..beba3ba 100644
--- a/daily_note.txt
+++ b/daily_note.txt
@@ -1,2 +1,2 @@
 release note
-flag: 0xV01D{HISTORY_REMEMBERS}
+sensitive note removed before shipping
```

This commit **removed** the flag from `daily_note.txt` and replaced it with a sanitized message.

### Initial Commit

```bash
$ git show 1d8be50
commit 1d8be508f5788a85edb1e0b3a8d08242f075ed0b
Author: CTF Builder <ctf@example.local>
Date:   Sun May 17 12:01:52 2026 +0300

    add first draft notes

diff --git a/README.md b/README.md
new file mode 100644
index 0000000..96dc6aa
--- /dev/null
+++ b/README.md
@@ -0,0 +1 @@
+Old notes were cleaned up before release. Check what changed.
diff --git a/daily_note.txt b/daily_note.txt
new file mode 100644
index 0000000..58207f1
--- /dev/null
+++ b/daily_note.txt
@@ -0,0 +1,2 @@
+release note
+flag: 0xV01D{HISTORY_REMEMBERS}
```

The flag was present in the initial commit's `daily_note.txt`.

---

## Alternative Methods

Even without using `git show`, there are multiple ways to recover the flag from the git object store:

### Via `git diff`

```bash
$ git diff 1d8be50 e067b54
diff --git a/daily_note.txt b/daily_note.txt
index 58207f1..beba3ba 100644
--- a/daily_note.txt
+++ b/daily_note.txt
@@ -1,2 +1,2 @@
 release note
-flag: 0xV01D{HISTORY_REMEMBERS}
+sensitive note removed before shipping
```

### Via the Reflog

```bash
$ git reflog
e067b54 HEAD@{0}: commit: clean release notes
1d8be50 HEAD@{1}: commit (initial): add first draft notes
```

### Direct Object Inspection

The git object store contains 7 objects (blobs, trees, and commits). The flag exists as a blob object that was never garbage-collected:

```bash
$ git fsck --unreachable --no-reflogs
```

---

## The Flag

```
0xV01D{HISTORY_REMEMBERS}
```

---

## Why This Works

Git is a **content-addressable storage system**. When you commit a file, its contents are hashed and stored as a blob object. When you later modify that file and make a new commit, the old blob is **not deleted** — it remains in `.git/objects/` until garbage collection (`git gc`) runs.

In this challenge:
1. The flag was committed in the initial commit as a blob.
2. A second commit replaced the file content with sanitized text.
3. The working tree shows only the sanitized version.
4. But the original blob is still in `.git/objects/`, fully recoverable through `git log`, `git show`, `git diff`, or direct object inspection.

This is a real-world security concern: **deleting a secret from a file and committing the change does not remove it from git history.** Anyone with access to the repository can recover it. This is why tools like `git filter-branch`, `BFG Repo-Cleaner`, or `git filter-repo` exist, and why secrets accidentally committed should trigger immediate credential rotation.

---

## Key Takeaways

1. **Git history is permanent (until gc).** Deleting a file or changing its contents in a new commit leaves the old data intact in the object store.

2. **Always check `git log` and `git diff`** when a challenge involves a git repository. The flag is often in a previous commit, not the working tree.

3. **Real-world implication:** Never commit secrets to git. Even if you remove them in a follow-up commit, they remain in history and can be recovered by anyone with repository access.

4. **The challenge name "release echo" is a hint.** The flag "echoed" back from the git history of what was supposed to be a clean release.

---

## Useful Git Forensics Commands

| Command | Purpose |
|---------|---------|
| `git log --oneline` | Quick commit overview |
| `git show <hash>` | Full diff of a specific commit |
| `git diff <hash1> <hash2>` | Diff between two commits |
| `git reflog` | View HEAD movement history |
| `git fsck --unreachable` | Find dangling/unreachable objects |
| `git cat-file -p <hash>` | Inspect any git object |
| `git log --all --graph --decorate` | Visual commit tree |
