# Image for skoop (Cloud Run). Builds the web app and the server in one
# context, linux/amd64, with no data volume: the database is Firestore and
# attachments go to object storage.
#
#   skoop apply resource cloudrun/web --source . (uses this file via deploy/skoop)
#
# The repo's scripts/Dockerfile stays the upstream multi-arch image.

FROM node:24-alpine AS web
WORKDIR /src/web
RUN corepack enable && corepack prepare pnpm@11.0.1 --activate
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
COPY web/patches ./patches
RUN pnpm install --frozen-lockfile
COPY web/ ./
COPY proto/ /src/proto/
RUN pnpm release

FROM golang:1.27.0-alpine AS server
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/server/frontend/dist ./server/frontend/dist
ARG VERSION=26.10
ARG COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
      -ldflags="-s -w -X github.com/usememos/memos/internal/version.Version=${VERSION} -X github.com/usememos/memos/internal/version.Commit=${COMMIT}" \
      -tags netgo,osusergo -o /out/memos ./cmd/memos

FROM alpine:3.21
RUN apk add --no-cache tzdata ca-certificates && \
    addgroup -g 10001 -S nonroot && adduser -u 10001 -S -G nonroot nonroot && \
    mkdir -p /var/opt/memos && chown nonroot:nonroot /var/opt/memos
COPY --from=server /out/memos /usr/local/bin/memos
USER nonroot
WORKDIR /var/opt/memos
ENV TZ=UTC MEMOS_PORT=8080 MEMOS_DATA=/var/opt/memos
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/memos"]
