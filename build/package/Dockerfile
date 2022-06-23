FROM alpine:3.14 as base
RUN apk update && apk add ca-certificates && update-ca-certificates && rm -rf /var/cache/apk/*

FROM scratch as final
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ARG target
COPY ${target} /app

# Including all certs just to keep the setup simple.
COPY root.key root.key
COPY root.crt root.crt
COPY intermediate.key intermediate.key
COPY intermediate.crt intermediate.crt
COPY server.key server.key
COPY server.crt server.crt
COPY client.key client.key
COPY client.crt client.crt

ENTRYPOINT ["/app"]