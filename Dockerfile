FROM alpine

COPY --chown=1001 ./bin/init-container /usr/local/bin/init-container

USER 1001

ENTRYPOINT ["/usr/local/bin/init-container"]
