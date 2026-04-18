# --- build ---
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/kms-manage ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/kmsctl ./cmd/kmsctl

# --- runtime ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/kms-manage /usr/local/bin/
COPY --from=build /out/kmsctl     /usr/local/bin/
COPY config/config.yaml /etc/kms-manage/config.yaml
EXPOSE 9290 9390
ENTRYPOINT ["/usr/local/bin/kms-manage"]
