with open('wallpaper.png', 'rb') as f:
    data = f.read()
    iend_pos = data.find(b'IEND')
    end_of_png = iend_pos + 8  # IEND type (4) + CRC (4)
    with open('extracted.7z', 'wb') as out:
        out.write(data[end_of_png:])
