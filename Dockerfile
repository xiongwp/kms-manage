# kms-manage 的 go.mod 通过 replace 指到 ../payment-util，
# 所以 docker build 的上下文必须是"父目录"，能同时看到兄弟仓。
#
# 联栈 build（推荐）：
#   cd <root>
#   docker build -f kms-manage/Dockerfile -t kms-manage:latest .
#
# docker-compose.yml 已经把 build.context 指到 `..`。

# --- build ---
FROM golang:1.25-alpine AS build
WORKDIR /src

# 两个兄弟仓一起进构建上下文
COPY payment-util  ./payment-util
COPY kms-manage    ./kms-manage

WORKDIR /src/kms-manage
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/kms-manage ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/kmsctl ./cmd/kmsctl

# --- runtime ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/kms-manage /usr/local/bin/
COPY --from=build /out/kmsctl     /usr/local/bin/
# 上下文在父目录，config 相对路径是 kms-manage/config
COPY kms-manage/config/config.yaml /etc/kms-manage/config.yaml
EXPOSE 9290 9390
ENTRYPOINT ["/usr/local/bin/kms-manage"]
