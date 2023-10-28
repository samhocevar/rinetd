# registry.access.redhat.com/ubi9/ubi:latest
FROM docker.io/redhat/ubi9:latest AS builder

RUN set -x \
    && dnf upgrade -y \
    # Install OS dependencies
    && dnf install -y \
        # C compiler, make and related tools
        gcc \
        make \
        cmake \
        automake

# Copy source to /build/
COPY . /build/

WORKDIR /build/
RUN set -x \
    # Build
    && ./bootstrap \
    && ./configure \
    && make \
    # Install
    && cd /build/ \
    && make install

# ==========================
# Final image
FROM docker.io/redhat/ubi9-minimal:latest

RUN set -x \
    && microdnf upgrade -y \
    && microdnf clean all

COPY --from=builder /usr/local/sbin/rinetd /usr/local/sbin/rinetd
