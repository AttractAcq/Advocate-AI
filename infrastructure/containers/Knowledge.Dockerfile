# syntax=docker/dockerfile:1
# Synthetic amd64 candidate. Both upstream artifacts are pinned by content.
FROM docker.io/library/postgres:17.12-alpine3.24@sha256:e80acae3f1109e8e4533618b594918936f2858c63afc7204c4773148a673add8 AS extension
ADD --checksum=sha256:cac0b10c360f05b2d521200105ba3697e773d4cd3731f5a915a7e37ebe0bea85 \
    https://github.com/pgvector/pgvector/archive/refs/tags/v0.8.7.tar.gz /tmp/pgvector.tar.gz
RUN apk add --no-cache build-base \
    && tar -xzf /tmp/pgvector.tar.gz -C /tmp \
    && make -C /tmp/pgvector-0.8.7 OPTFLAGS="" with_llvm=0 \
    && make -C /tmp/pgvector-0.8.7 DESTDIR=/staged with_llvm=0 install

FROM docker.io/library/postgres:17.12-alpine3.24@sha256:e80acae3f1109e8e4533618b594918936f2858c63afc7204c4773148a673add8
COPY --from=extension /staged/usr/local/ /usr/local/
COPY --from=extension /tmp/pgvector-0.8.7/LICENSE /usr/share/doc/pgvector/LICENSE
