FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY mpcd /usr/local/bin/mpcd
EXPOSE 8081
ENTRYPOINT ["mpcd"]
