# Reference Jira gateway: static Go binary on distroless, non-root.
# Base images are pinned by index digest (multi-arch); refresh both together.
FROM docker.io/library/golang:1.26@sha256:f6946db66567acc1497655237e58f06ec3a57478a5e0d67fca29d2ffcf2ea136 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/jira-gateway ./cmd/jira-gateway

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/jira-gateway /jira-gateway
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/jira-gateway"]
CMD ["-config", "/etc/jira-gateway/config/config.json"]
