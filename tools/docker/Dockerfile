FROM alpine AS build

ARG OPENSSL_TAG=openssl-3.6.0
ARG LIBOQS_TAG=0.15.0
ARG OQSPROVIDER_TAG=0.11.0
ARG BASEDIR=/opt
ARG INSTALLDIR=${BASEDIR}/open62541
ARG OSSLDIR=${BASEDIR}/openssl/.openssl

# Build Stage (1/2)
RUN apk add --no-cache cmake gcc git g++ \
    musl-dev mbedtls-dev python3 py3-pip \
    make openssl openssl-dev ninja autoconf \
    linux-headers && rm -rf /var/cache/apk/*

WORKDIR /opt

# Descargar oqs y oqs-providers
RUN git clone --depth 1 --branch ${LIBOQS_TAG} https://github.com/open-quantum-safe/liboqs \
    && git clone --depth 1 --branch ${OQSPROVIDER_TAG} https://github.com/open-quantum-safe/oqs-provider.git \
    && git clone --depth 1 --branch ${OPENSSL_TAG} https://github.com/openssl/openssl.git

# Compilar liboqs
WORKDIR /opt/liboqs/build
RUN cmake -G"Ninja"  \
    -DOQS_DIST_BUILD=ON  \
    -DBUILD_SHARED_LIBS=OFF  \
    -DCMAKE_INSTALL_PREFIX="${INSTALLDIR}" ..  \
    && ninja -j"$(nproc)" && ninja install

# Configurar openssl.cnf para usar oqs-provider
RUN mkdir -p ${OSSLDIR=}/ssl && \
    cp /opt/openssl/apps/openssl.cnf ${OSSLDIR}/ssl/ && \
    sed -i "s/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect/g" ${OSSLDIR}/ssl/openssl.cnf && \
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[oqsprovider_sect\]\nactivate = 1\n/g" ${OSSLDIR}/ssl/openssl.cnf && \
    sed -i "s/providers = provider_sect/providers = provider_sect\nssl_conf = ssl_sect\n\n\[ssl_sect\]\nsystem_default = system_default_sect\n\n\[system_default_sect\]\nGroups = \$ENV\:\:DEFAULT_GROUPS\n/g" ${OSSLDIR}/ssl/openssl.cnf && \
    sed -i "s/HOME\t\t\t= ./HOME\t\t= .\nDEFAULT_GROUPS\t= ${DEFAULT_GROUPS}/g" ${OSSLDIR}/ssl/openssl.cnf

# Compilar oqs-provider
WORKDIR /opt/oqs-provider
RUN rm -rf build && \
    cmake -DCMAKE_BUILD_TYPE=Debug \
            -DOPENSSL_ROOT_DIR="${OSSLDIR}" \
            -DCMAKE_PREFIX_PATH="${INSTALLDIR}" \
            -S . -B build && \
    cmake --build build && \
    MODULESDIR=$(find "${OSSLDIR}" -name ossl-modules) && \
    export MODULESDIR && \
    cp build/lib/oqsprovider.so "${MODULESDIR}" && \
    mkdir -p "${OSSLDIR}/lib64" && \
    ln -s "${OSSLDIR}/lib/ossl-modules" "${OSSLDIR}/lib64" && \
    rm -rf "${INSTALLDIR:?}/lib64"

WORKDIR ${INSTALLDIR}
ENV PATH="${INSTALLDIR}/sbin:${OSSLDIR}/bin:${PATH}"

ARG OSSLDIR=${BASEDIR}/openssl/.openssl

COPY . ${INSTALLDIR}
# Get all the git tags to make sure we detect the correct version with git describe
WORKDIR ${INSTALLDIR}

# Compilar open62541 con encryption openssl
WORKDIR ${INSTALLDIR}/build
RUN cmake -DBUILD_SHARED_LIBS=ON \
      -DCMAKE_BUILD_TYPE=Release \
      -DUA_BUILD_EXAMPLES=ON \
      -DUA_ENABLE_ENCRYPTION=OPENSSL \
      -DUA_ENABLE_SUBSCRIPTIONS=ON \
      -DUA_ENABLE_SUBSCRIPTIONS_EVENTS=ON \
      -DUA_NAMESPACE_ZERO=FULL \
     ${INSTALLDIR} && \
    make -j && \
    make install
WORKDIR ${INSTALLDIR}

# Generate certificates
RUN apk add --no-cache python3-dev linux-headers openssl && rm -rf /var/cache/apk/* && \
    pip3 install --no-cache-dir netifaces==0.10.9

# Final Stage (2/2)
FROM alpine AS server

RUN apk add --no-cache openssl openssl-dev musl-dev
RUN --mount=src=/,dst=/artifacts,from=build \
    mkdir -p ${INSTALLDIR}/pki \
    && mkdir -p /usr/local/lib64/cmake/open62541 \
    && mkdir -p /usr/local/lib64/pkgconfig \
    && mkdir -p /usr/local/share/open62541/tools \
    && mkdir -p /usr/local/include/open62541 \
    && mkdir -p /usr/local/bin \
    && cp -r /artifact ${INSTALLDIR}/pki/created ${INSTALLDIR}/pki/created \
    && cp -r /artifact ${INSTALLDIR}/build/bin/examples ${INSTALLDIR} \
    && cp -r /artifacts/usr/local/lib64/libopen62541* /usr/local/lib64/ \
    && cp -r /artifacts/usr/local/lib64/cmake/open62541/ /usr/local/lib64/cmake/open62541/ \
    && cp -r /artifacts/usr/local/lib64/pkgconfig/open62541.pc /usr/local/lib64/pkgconfig/open62541.pc \
    && cp -r /artifacts/usr/local/share/open62541/tools/certs /usr/local/share/open62541/tools/certs \
    && cp -r /artifacts/usr/local/include/open62541/ /usr/local/include/open62541/ \
    && cp -r /artifacts/usr/local/include/oqs/ /usr/local/include/oqs/ \
    && cp /artifacts/usr/local/include/ms_stdint.h /usr/local/include/ms_stdint.h \
    && cp /artifacts/usr/local/include/ziptree.h /usr/local/include/ziptree.h \
    && cp /artifacts/usr/local/include/aa_tree.h /usr/local/include/aa_tree.h \
    && cp /artifacts/usr/local/bin/ua_server_ctt.exe /usr/local/bin/ua_server_ctt.exe \
    && cp /artifacts/usr/local/bin/ua_client /usr/local/bin/ua_client \
    && cp /artifacts/usr/local/lib/ua_server_encryption /usr/local/lib/ua_server_encryption \
    && cp /artifacts/usr/local/lib/liboqs* /usr/local/lib/

ENV LD_LIBRARY_PATH=/usr/local/lib64/

EXPOSE 4840

ENTRYPOINT ["/entrypoint.sh"]
