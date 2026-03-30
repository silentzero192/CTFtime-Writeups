import matplotlib.pyplot as plt
import struct

def solve():
    with open('data.txt', 'r') as f:
        lines = f.readlines()

    x, y = 0, 0
    strokes = []

    for line in lines:
        line = line.strip()
        if not line: continue
        try:
            data = bytes.fromhex(line)
            if len(data) != 7: continue
            status = data[1]
            rel_x = struct.unpack('<h', data[2:4])[0]
            rel_y = struct.unpack('<h', data[4:6])[0]
            x += rel_x
            y += rel_y
            strokes.append((x, -y, status))
        except: continue

    def zoom_plot(xmin, xmax, ymin, ymax, filename, title):
        plt.figure(figsize=(10, 6))
        for i in range(1, len(strokes)):
            p1 = strokes[i-1]
            p2 = strokes[i]
            if p1[2] in [1, 2] and p2[2] in [1, 2]:
                plt.plot([p1[0], p2[0]], [p1[1], p2[1]], color='blue' if p2[2] == 2 else 'red', linewidth=2)
        plt.xlim(xmin, xmax)
        plt.ylim(ymin, ymax)
        plt.title(title)
        plt.grid(True)
        plt.savefig(filename)
        print(f"Saved {filename}")

    # Zoom on "white"
    zoom_plot(1100, 1900, -950, -600, 'zoom_white.png', 'Zoom: white')
    # Zoom on "colour"
    zoom_plot(1900, 3000, -950, -600, 'zoom_colour.png', 'Zoom: colour')
    # Zoom on "r153"
    zoom_plot(1900, 2500, -1150, -850, 'zoom_r153.png', 'Zoom: r153')
    # Zoom on "th3_fl4g"
    zoom_plot(2400, 3400, -1250, -950, 'zoom_flag.png', 'Zoom: th3_fl4g')

if __name__ == "__main__":
    solve()
