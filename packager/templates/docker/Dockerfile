FROM alpine:latest

COPY "{{cpkg_binary}}" "/{{cpkg_name}}-server"

RUN mkdir -p "/{{cpkg_name}}/tls" && \
    mkdir -p "/{{cpkg_name}}/signer" && \
    mkdir -p "/{{cpkg_name}}/signing" && \
    chmod a+x "/{{cpkg_name}}" && \
    mkdir /lib64 && \
    ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2

COPY dist/aaasvc.json "/{{cpkg_name}}/config.json"

ENTRYPOINT "/{{cpkg_name}}-server"
CMD ["run", "--config", "/{{cpkg_name}}/config.json"]