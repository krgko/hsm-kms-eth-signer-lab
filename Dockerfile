FROM alpine:3

ENV SOFTHSM2_VERSION=2.6.1 \
    SOFTHSM2_SOURCES=/tmp/softhsm2 \
    PKCS11_PROXY_SOURCES=/tmp/pkcs11-proxy

# Install build dependencies
RUN apk --update --no-cache add \
        alpine-sdk \
        autoconf \
        automake \
        git \
        libtool \
        libseccomp-dev \
        cmake \
        p11-kit-dev \
        openssl-dev \
        stunnel

# Build and install SoftHSM2
RUN git clone https://github.com/opendnssec/SoftHSMv2.git ${SOFTHSM2_SOURCES}
WORKDIR ${SOFTHSM2_SOURCES}

RUN git checkout ${SOFTHSM2_VERSION} -b ${SOFTHSM2_VERSION} \
    && sh autogen.sh \
    && ./configure --prefix=/usr/local \
    && make \
    && make install

# Build and install pkcs11-proxy
RUN git clone https://github.com/SUNET/pkcs11-proxy ${PKCS11_PROXY_SOURCES} 
WORKDIR ${PKCS11_PROXY_SOURCES}

RUN cmake . && make && make install

WORKDIR /root
RUN rm -fr ${SOFTHSM2_SOURCES} && rm -fr ${PKCS11_PROXY_SOURCES}

# install pkcs11-tool
RUN apk --update --no-cache add opensc && \
    echo "0:/var/lib/softhsm/slot0.db" > /etc/softhsm2.conf && \
    softhsm2-util --init-token --slot 0 --label key --pin 1234 --so-pin 0000

EXPOSE 5657
ENV PKCS11_DAEMON_SOCKET="tcp://0.0.0.0:5657"
CMD [ "/usr/local/bin/pkcs11-daemon", "/usr/local/lib/softhsm/libsofthsm2.so" ]
