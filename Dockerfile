FROM alpine:3
LABEL maintainer="EasyPi Software Foundation"
ENV DEBIAN_FRONTEND=noninteractive
ARG RINETD_VERSION=0.73
ARG RINETD_URL=https://github.com/samhocevar/rinetd/releases/download/v${RINETD_VERSION}/rinetd-${RINETD_VERSION}.tar.gz
RUN apk update \
&& apk add --no-cache automake autoconf m4 perl curl tar build-base \
&& mkdir rinetd \
&& cd rinetd \
&& curl -sSL $RINETD_URL | tar xz --strip 1 \
&& ./configure --prefix=/usr --sysconfdir=/etc/rinetd \
&& make \
&& make install \
&& cd .. \
&& rm -r rinetd \
&& apk del build-base curl tar automake autoconf m4 perl
VOLUME /etc/rinetd
CMD ["rinetd", "-f", "-c", "/etc/rinetd/rinetd.conf"]
