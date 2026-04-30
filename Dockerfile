FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go test ./... && CGO_ENABLED=0 go build -o /out/ct-cve ./cmd/ct-cve

FROM alpine:3.20
RUN addgroup -S ct-cve && adduser -S -G ct-cve ct-cve
USER ct-cve
COPY --from=build /out/ct-cve /usr/local/bin/ct-cve
EXPOSE 8080
ENTRYPOINT ["ct-cve"]

