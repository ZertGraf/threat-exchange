# syntax=docker/dockerfile:1
# pin the patch release so release builds get the latest standard library fixes.
FROM golang:1.26.10-bookworm AS development
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

FROM development AS build
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=build /out/server /server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/server"]
