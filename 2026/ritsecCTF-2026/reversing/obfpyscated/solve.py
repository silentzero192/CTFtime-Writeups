import io
import socket
import ssl
from PIL import Image


HOST = "meow.sylvie.fyi"
PORT = 443
REQUEST = (
    b"GET /static/ritsec_catgirl.png HTTP/1.1\r\n"
    b"Host: meow.sylvie.fyi\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

COORDS = (
    (139, 766), (136, 759), (177, 440), (95, 810), (154, 479),
    (136, 758), (179, 439), (95, 808), (158, 456), (136, 758),
    (191, 551), (99, 796), (159, 522), (136, 758), (152, 485),
    (155, 458), (99, 796), (95, 809), (136, 758), (95, 808),
    (159, 522), (136, 758), (179, 439), (95, 808), (158, 456),
    (191, 551), (136, 758), (155, 458), (95, 808), (159, 512),
    (95, 809), (136, 758), (179, 439), (95, 808), (158, 456),
    (136, 758), (159, 512), (155, 458), (95, 808), (158, 456),
    (190, 496), (153, 479), (136, 758), (195, 443), (99, 796),
    (156, 456), (94, 810), (136, 758), (153, 470), (94, 810),
    (152, 485), (152, 485), (161, 450), (191, 551), (136, 758),
    (153, 479), (94, 810), (154, 463), (154, 464), (159, 512),
    (95, 810), (158, 521), (159, 522), (97, 786), (233, 533),
)


def fetch_png():
    wrapped = ssl.create_default_context().wrap_socket(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM),
        server_hostname=HOST,
    )
    wrapped.connect((HOST, PORT))
    wrapped.sendall(REQUEST)

    response = b""
    while True:
        chunk = wrapped.recv(4096)
        if not chunk:
            break
        response += chunk

    wrapped.close()
    return response[response.index(b"\x89PNG"):]


def recover_flag(png_bytes):
    image = Image.open(io.BytesIO(png_bytes))
    chars = []
    for coord in COORDS:
        r, g, b = image.getpixel(coord)
        chars.append(chr(r ^ g ^ b))
    return "".join(chars)


def main():
    png_bytes = fetch_png()
    print(recover_flag(png_bytes))


if __name__ == "__main__":
    main()
