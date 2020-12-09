FROM scratch

COPY bin /init-container
ENTRYPOINT ["/init-container"]
