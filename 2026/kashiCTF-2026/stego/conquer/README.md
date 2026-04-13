# Conquer - Writeup

## Challenge

- **Name:** `conquer`
- **Category:** `Steganography`
- **Description:** `I like to save my files as pdfs. Kashi kings hate 184`

## TL;DR

The provided `flag.pdf` was not a real PDF. It was actually a raw `PPM` image with a fake `.pdf` extension and a forged image height in the header. Fixing the height exposed hidden rows at the bottom of the image, which contained the flag.

## Files

- `flag.pdf`

## Initial Recon

The description strongly hints that the file may not really be a PDF:

> I like to save my files as pdfs.

So the first step was to inspect the file type.

```bash
file flag.pdf
exiftool flag.pdf
pdfinfo flag.pdf
```

Output showed:

- `file` identified it as `Netpbm image data`
- `exiftool` identified it as `PPM`
- `pdfinfo` failed because the file was not a valid PDF

That means the extension is fake and the challenge is really about an image.

## Looking At The Header

Checking the first few bytes:

```bash
xxd -l 32 flag.pdf
```

Header:

```text
P6
284 150
255
```

This is the header of a binary `PPM` image:

- `P6` = raw RGB PPM
- width = `284`
- height = `150`
- max color value = `255`

But the challenge description also says:

> Kashi kings hate 184

That looked suspicious, so I checked whether the file size matched the declared dimensions.

For a `P6` PPM, image data size should be:

```text
width * height * 3
```

If the height were really `150`, the pixel data would be:

```text
284 * 150 * 3 = 127800 bytes
```

But the full file size was much larger. After subtracting the 15-byte header, the remaining data matched:

```text
284 * 185 * 3 = 157620 bytes
```

So the real height is `185`, not `150`.

This means the image contains **35 hidden rows**:

```text
185 - 150 = 35
```

## Recovering The Hidden Part

I rebuilt the image with the corrected height:

```bash
printf 'P6\n284 185\n255\n' > /tmp/flag_fixed.ppm
dd if=flag.pdf of=/tmp/flag_fixed.ppm bs=1 skip=15 seek=15 conv=notrunc status=none
```

Then converted it to PNG for easy viewing:

```bash
convert /tmp/flag_fixed.ppm /tmp/flag_fixed.png
```

The corrected image revealed extra content at the bottom. To isolate it:

```bash
convert /tmp/flag_fixed.ppm -crop 284x35+0+150 +repage /tmp/flag_hidden_strip.png
```

That hidden strip contained the flag text.

## Flag

```text
kashiCTF{ILOVEkashi}
```

## Final Notes

The key trick was:

1. Ignore the `.pdf` extension.
2. Recognize the file as a `PPM`.
3. Verify whether the declared dimensions matched the actual byte count.
4. Restore the true height to reveal the hidden rows.

This is a nice example of hiding data by lying in the image header instead of modifying the visible image itself.
