FROM python:3.10.2-slim

RUN pip install --no-cache-dir pycryptodome pillow

WORKDIR /run

COPY meow.py .

CMD [ "python3", "meow.py" ]