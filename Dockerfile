# syntax=docker/dockerfile:1.6
FROM golang:1.25 as builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
RUN go mod tidy && go mod download github.com/bwmarrin/discordgo
RUN go build -ldflags="-s -w" -o /out/ptbot ./main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /out/ptbot /app/ptbot
USER nonroot:nonroot
ENTRYPOINT ["/app/ptbot"]
CMD ["-config", "/data/config.json"]
