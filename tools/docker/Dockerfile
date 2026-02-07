# Define build arguments for version tags, installation paths, and configurations
ARG ALPINE_VERSION=3.21
ARG OPENSSL_TAG=openssl-3.6.0
ARG LIBOQS_TAG=0.15.0
ARG OQSPROVIDER_TAG=0.11.0

ARG INSTALLDIR_OPENSSL=/opt/openssl
ARG INSTALLDIR_LIBOQS=/opt/liboqs

ARG SIG_ALG="mayo2"

# Stage 1: Build OpenSSL
FROM alpine:${ALPINE_VERSION} AS buildopenssl
ARG OPENSSL_TAG
ARG INSTALLDIR_OPENSSL
ARG INSTALLDIR_LIBOQS
ARG SIG_ALG

LABEL version="4"

RUN apk --no-cache add build-base linux-headers libtool \
                       automake autoconf make git wget \
                       gcc g++ musl-dev

WORKDIR /optbuild
RUN git clone --depth 1 --branch ${OPENSSL_TAG} https://github.com/openssl/openssl.git

# Configure, compile, and install OpenSSL
WORKDIR /optbuild/openssl
RUN LDFLAGS="-Wl,-rpath -Wl,${INSTALLDIR_OPENSSL}/lib64" \
    ./config shared --prefix=${INSTALLDIR_OPENSSL} && \
    make -j"$(nproc)" && make install && \
    if [ -d ${INSTALLDIR_OPENSSL}/lib64 ]; then ln -s ${INSTALLDIR_OPENSSL}/lib64 ${INSTALLDIR_OPENSSL}/lib; fi && \
    if [ -d ${INSTALLDIR_OPENSSL}/lib ]; then ln -s ${INSTALLDIR_OPENSSL}/lib ${INSTALLDIR_OPENSSL}/lib64; fi

# Stage 2: Build liboqs
FROM alpine:${ALPINE_VERSION} AS buildliboqs
ARG LIBOQS_TAG
ARG INSTALLDIR_OPENSSL
ARG INSTALLDIR_LIBOQS
ARG SIG_ALG

LABEL version="4"

RUN apk --no-cache add build-base linux-headers libtool \
                       automake autoconf cmake ninja \
                       make git wget gcc g++ musl-dev

# Copy the OpenSSL installation from the previous stage
COPY --from=buildopenssl ${INSTALLDIR_OPENSSL} ${INSTALLDIR_OPENSSL}

WORKDIR /optbuild
RUN git clone --depth 1 --branch ${LIBOQS_TAG} https://github.com/open-quantum-safe/liboqs

# Configure and compile liboqs using the Ninja build system
WORKDIR /optbuild/liboqs/build
RUN cmake -G"Ninja" ..  \
    -DOPENSSL_ROOT_DIR=${INSTALLDIR_OPENSSL} \
    -DCMAKE_INSTALL_PREFIX=${INSTALLDIR_LIBOQS} && \
    ninja install

# Stage 3: Build oqs-provider
FROM alpine:${ALPINE_VERSION} AS buildoqsprovider
ARG OQSPROVIDER_TAG
ARG INSTALLDIR_OPENSSL
ARG INSTALLDIR_LIBOQS
ARG SIG_ALG

LABEL version="4"

RUN apk --no-cache add build-base linux-headers \
                       libtool cmake ninja git wget \
                       gcc g++ musl-dev

WORKDIR /optbuild
RUN git clone --depth 1 --branch ${OQSPROVIDER_TAG} https://github.com/open-quantum-safe/oqs-provider.git

# Copy previously built OpenSSL and liboqs installations
COPY --from=buildopenssl ${INSTALLDIR_OPENSSL} ${INSTALLDIR_OPENSSL}
COPY --from=buildliboqs ${INSTALLDIR_LIBOQS} ${INSTALLDIR_LIBOQS}

# Build, install, and configure the oqs-provider
WORKDIR /optbuild/oqs-provider
RUN liboqs_DIR=${INSTALLDIR_LIBOQS} \
    cmake -DOPENSSL_ROOT_DIR=${INSTALLDIR_OPENSSL} \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_PREFIX_PATH=${INSTALLDIR_OPENSSL} -S . -B _build && \
    cmake --build _build && \
    cmake --install _build && \
    cp _build/lib/oqsprovider.so ${INSTALLDIR_OPENSSL}/lib64/ossl-modules && \
    sed -i "s/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect/g" ${INSTALLDIR_OPENSSL}/ssl/openssl.cnf && \
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[oqsprovider_sect\]\nactivate = 1\n/g" ${INSTALLDIR_OPENSSL}/ssl/openssl.cnf && \
    sed -i "s/providers = provider_sect/providers = provider_sect\nssl_conf = ssl_sect\n\n\[ssl_sect\]\nsystem_default = system_default_sect\n\n\[system_default_sect\]\nGroups = \$ENV\:\:DEFAULT_GROUPS\n/g" ${INSTALLDIR_OPENSSL}/ssl/openssl.cnf && \
    sed -i "s/HOME\t\t\t= ./HOME           = .\nDEFAULT_GROUPS = frodo640aes/g" ${INSTALLDIR_OPENSSL}/ssl/openssl.cnf

# Update PATH to include the newly installed OpenSSL binaries
WORKDIR ${INSTALLDIR_OPENSSL}/bin
ENV PATH="${INSTALLDIR_OPENSSL}/bin:${PATH}"

# Stage 4: Create Minimal Runtime Image
FROM alpine:${ALPINE_VERSION} AS build
ARG INSTALLDIR_OPENSSL
ARG INSTALLDIR_LIBOQS
ARG SIG_ALG

# Retain only the OpenSSL installation for the final image
COPY --from=buildoqsprovider ${INSTALLDIR_OPENSSL} ${INSTALLDIR_OPENSSL}
COPY --from=buildoqsprovider ${INSTALLDIR_LIBOQS} ${INSTALLDIR_LIBOQS}

# Ensure the PATH uses the newly built OpenSSL binaries
ENV PATH="${INSTALLDIR_OPENSSL}/bin:${PATH}"

RUN apk add --no-cache cmake gcc g++ musl-dev \
make git linux-headers \
libc6-compat pkgconf python3-dev

RUN echo '#pragma once' > /usr/include/bits/stdio_lim.h && \
echo '#include <stdio.h>' >> /usr/include/bits/stdio_lim.h && \
echo '#include <limits.h>' >> /usr/include/bits/stdio_lim.h

COPY . /app

WORKDIR /app

RUN git submodule update --init --recursive

# Set openssl env variables
ENV OPENSSL_INCLUDE_DIR="${INSTALLDIR_OPENSSL}/include"
ENV OPENSSL_ROOT_DIR="${INSTALLDIR_OPENSSL}/"

# Manually link oqs to sys libraries 
RUN ln -s ${INSTALLDIR_LIBOQS}/lib/liboqs.a /usr/lib/
RUN ln -s ${INSTALLDIR_LIBOQS}/include/* /usr/include/

# Compilar open62541 con encryption openssl
RUN cmake -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_BUILD_TYPE=Release \
          -DUA_BUILD_EXAMPLES=ON \
          -DUA_ENABLE_ENCRYPTION=OPENSSL \
          -DUA_ENABLE_SUBSCRIPTIONS=ON \
          -DUA_ENABLE_SUBSCRIPTIONS_EVENTS=ON \
          -DUA_NAMESPACE_ZERO=FULL \
          -DCMAKE_C_FLAGS="-D_GNU_SOURCE -Wno-deprecated-declarations -Wno-c++-compat" \
          /app && \
    make -j "$(nproc)" && \
    make install

# ==============================================================================

FROM alpine:${ALPINE_VERSION} AS server

ARG INSTALLDIR_LIBOQS
ARG INSTALLDIR_OPENSSL

COPY --from=buildoqsprovider ${INSTALLDIR_OPENSSL} ${INSTALLDIR_OPENSSL}
COPY --from=buildoqsprovider ${INSTALLDIR_LIBOQS} ${INSTALLDIR_LIBOQS}

ENV OPENSSL_INCLUDE_DIR="${INSTALLDIR_OPENSSL}/include"
ENV OPENSSL_ROOT_DIR="${INSTALLDIR_OPENSSL}/"

RUN mkdir -p /usr/include

RUN ln -s ${INSTALLDIR_LIBOQS}/lib/liboqs.a /usr/lib/
RUN ln -s ${INSTALLDIR_LIBOQS}/include/* /usr/include/

WORKDIR /app

RUN --mount=src=/,dst=/artifacts,from=build \
    mkdir -p /usr/local/lib/cmake/open62541 \
    && mkdir -p /usr/local/lib/pkgconfig \
    && mkdir -p /usr/local/share/open62541/tools \
    && mkdir -p /usr/local/include/open62541 \
    && mkdir -p /usr/local/bin \
    && cp -r /artifacts/usr/local/lib/libopen62541* /usr/local/lib/ \
    && cp -r /artifacts/usr/local/lib/cmake/open62541/ /usr/local/lib/cmake/open62541/ \
    && cp -r /artifacts/usr/local/lib/pkgconfig/open62541.pc /usr/local/lib/pkgconfig/open62541.pc \
    && cp -r /artifacts/usr/local/include/open62541/ /usr/local/include/open62541/ \
    && cp /artifacts/app/bin/examples/server_encryption . \
    && cp /artifacts/app/bin/examples/client_encryption . \
    && cp /artifacts/app/tools/entrypoint.sh .

RUN chmod +x /app/entrypoint.sh

EXPOSE 4840
CMD ["/app/entrypoint.sh"]
