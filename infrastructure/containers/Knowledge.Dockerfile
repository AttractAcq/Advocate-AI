# syntax=docker/dockerfile:1
# Synthetic amd64 candidate. Both upstream artifacts are pinned by content.
FROM docker.io/library/postgres:17.12-alpine3.24@sha256:e80acae3f1109e8e4533618b594918936f2858c63afc7204c4773148a673add8 AS extension
ADD --checksum=sha256:cac0b10c360f05b2d521200105ba3697e773d4cd3731f5a915a7e37ebe0bea85 \
    https://github.com/pgvector/pgvector/archive/refs/tags/v0.8.7.tar.gz /tmp/pgvector.tar.gz
RUN apk add --no-cache build-base \
    && tar -xzf /tmp/pgvector.tar.gz -C /tmp \
    && make -C /tmp/pgvector-0.8.7 OPTFLAGS="" with_llvm=0 \
    && make -C /tmp/pgvector-0.8.7 DESTDIR=/staged with_llvm=0 install

FROM docker.io/library/postgres:17.12-alpine3.24@sha256:e80acae3f1109e8e4533618b594918936f2858c63afc7204c4773148a673add8 AS assembled
COPY --from=extension /staged/usr/local/ /usr/local/
COPY --from=extension /tmp/pgvector-0.8.7/LICENSE /usr/share/doc/pgvector/LICENSE
RUN apk add --no-cache su-exec=0.3-r0 libxml2=2.13.9-r3 \
    && rm /usr/local/bin/gosu \
    && ln -s /sbin/su-exec /usr/local/bin/gosu \
    && gosu postgres true

# Copy the final filesystem into one new layer so the removed base-image Go
# binary is absent from the distributed archive and its offline scan.
FROM scratch
COPY --from=assembled / /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=en_US.utf8 PG_MAJOR=17 PG_VERSION=17.12 \
    PGDATA=/var/lib/postgresql/data
VOLUME /var/lib/postgresql/data
ENTRYPOINT ["docker-entrypoint.sh"]
STOPSIGNAL SIGINT
EXPOSE 5432
CMD ["postgres"]
