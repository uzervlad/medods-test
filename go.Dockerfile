FROM golang:1.24.5-alpine

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -v -o /usr/local/bin/medods

CMD ["medods"]
