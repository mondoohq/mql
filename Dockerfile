# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1

FROM alpine:3.24.2 AS root
RUN apk update &&\
    apk add ca-certificates wget tar &&\
    rm -rf /var/cache/apk/*
COPY mql /usr/local/bin
ENTRYPOINT ["mql"]
CMD ["help"]

# Rootless version of the container
FROM root AS rootless

RUN addgroup -S mondoo && adduser -S -G mondoo mondoo
USER mondoo