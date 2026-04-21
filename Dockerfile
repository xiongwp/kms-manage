# kms-manage Dockerfile — 自包含构建
#
# 以前要求 docker build context 是"父目录"以看到 ../payment-util。
# 当 outer docker-compose 用 `context: ./kms-manage` 时，sibling COPY 会失败。
#
# 现在 Dockerfile 自己 git-clone payment-util 到 /src/payment-util，
# go.mod 里的 `replace ../payment-util` 依赖的相对路径仍然成立。
#
# 私仓 clone 通过 BuildKit secret 传 token：
#   services.kms.build.secrets:
#     - GITHUB_TOKEN
# 然后 GITHUB_TOKEN=ghp_xxx docker compose build；
# 公仓不带 secret 也行。
#
# 默认拉 main；覆盖：--build-arg PAYMENT_UTIL_REF=<branch>

# --- build ---
FROM golang:1.25-alpine AS build
RUN apk add --no-cache git ca-certificates
WORKDIR /src

# GOFLAGS=-mod=mod 让 go build 在 go.sum 缺条目时自动补（payment-util 是新
# 加进来的 replace 依赖，kms-manage 的 go.sum 还没对应 hash；go mod download
# 只下主 go.mod 的直接依赖，不会自动往 go.sum 写 replaced 模块的传递依赖。
# -mod=mod 在 build 时按需下载并写回 go.sum）。
ENV GOFLAGS=-mod=mod
ENV GOTOOLCHAIN=auto

ARG PAYMENT_UTIL_REF=main
RUN --mount=type=secret,id=GITHUB_TOKEN,required=false \
    set -eu; \
    TOKEN=""; \
    [ -f /run/secrets/GITHUB_TOKEN ] && TOKEN="$(cat /run/secrets/GITHUB_TOKEN)"; \
    if [ -n "$TOKEN" ]; then \
        URL="https://x-access-token:${TOKEN}@github.com/xiongwp/payment-util.git"; \
    else \
        URL="https://github.com/xiongwp/payment-util.git"; \
    fi; \
    git clone --depth=1 --branch "${PAYMENT_UTIL_REF}" "$URL" /src/payment-util

# 这个仓自己的代码
COPY . /src/kms-manage

WORKDIR /src/kms-manage
# tidy 一下，把 payment-util 传递进来的新 indirect（OTel 等）写进 go.sum；
# 比纯 GOFLAGS=-mod=mod 稳妥，因为某些 build 工具链仍会按 go.sum 校验。
RUN go mod tidy
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/kms-manage ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/kmsctl ./cmd/kmsctl

# --- runtime ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/kms-manage /usr/local/bin/
COPY --from=build /out/kmsctl     /usr/local/bin/
# 构建上下文是 kms-manage 自身目录，config 相对路径就是 config/
COPY config/config.yaml /etc/kms-manage/config.yaml
EXPOSE 9290 9390
ENTRYPOINT ["/usr/local/bin/kms-manage"]
