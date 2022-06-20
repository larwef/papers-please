FROM alpine:3.14 as base
RUN apk update && apk add ca-certificates && update-ca-certificates && rm -rf /var/cache/apk/*

FROM scratch as final
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ARG target
COPY ${target} /app

ENTRYPOINT ["/app"]