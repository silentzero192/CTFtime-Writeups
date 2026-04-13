FROM golang:1.24.0-alpine AS builder

RUN apk update && apk add --no-cache git gcc musl-dev make

WORKDIR /app

COPY ./readflag .

RUN go mod download

RUN go build -o readflag .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

COPY --from=builder /app/readflag /readflag
COPY flag.txt /flag.txt
RUN chmod 4111 /readflag
RUN chmod 400 /flag.txt

RUN addgroup -S poastboard && adduser poastboard -G poastboard -D -H
WORKDIR /app

COPY templates ./templates
COPY config.toml .
COPY flag.png .
COPY ./build ./

RUN chmod -R 644 /app
RUN chmod u+x,g+x,o+x /app/poastboard /app /app/templates /app/templates/static
RUN chown -R poastboard:poastboard /app

RUN JWT_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) && \
    echo "jwt_key = \"$JWT_KEY\"" >> ./config.toml

EXPOSE 8080

USER poastboard

CMD ["./poastboard"]