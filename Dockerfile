ARG UBUNTU_VERSION=24.04
ARG LIBOQS_VERSION=0.15.0
ARG LIBOQS_DIR=/opt/liboqs
ARG PQC_PAKES_DIR=/opt/pqc-pakes
ARG CFLAGS="-I${LIBOQS_DIR}/include -I ${PQC_PAKES_DIR}/include"
ARG LDFLAGS="-L${LIBOQS_DIR}/lib -L${PQC_PAKES_DIR}/lib -Wl,-rpath,${LIBOQS_DIR}/lib:${PQC_PAKES_DIR}/lib"

FROM ubuntu:${UBUNTU_VERSION} AS build
ARG LIBOQS_VERSION
ARG LIBOQS_DIR
ARG PQC_PAKES_DIR
ARG CFLAGS
ARG LDFLAGS
RUN apt-get update
RUN apt-get -y install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind git
WORKDIR /build
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git
WORKDIR /build/liboqs/build
RUN cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=${LIBOQS_DIR} ..
RUN ninja
RUN ninja install
WORKDIR /build/pqc-pakes
COPY CMakeLists.txt ./
COPY src/ ./src/
WORKDIR /build/pqc-pakes/build
ENV PQC_PAKES_DIR=${PQC_PAKES_DIR}
RUN cmake ..
RUN make
RUN make install

FROM ubuntu:${UBUNTU_VERSION} AS dev
ARG LIBOQS_DIR
ARG PQC_PAKES_DIR
ARG CFLAGS
ARG LDFLAGS
COPY --from=build ${LIBOQS_DIR} ${LIBOQS_DIR}
COPY --from=build ${PQC_PAKES_DIR} ${PQC_PAKES_DIR}
RUN apt-get update
RUN apt-get -y install gcc cmake
ENV LIBOQS_DIR=${LIBOQS_DIR}
ENV PQC_PAKES_DIR=${PQC_PAKES_DIR}
ENV CFLAGS=${CFLAGS}
ENV LDFLAGS=${LDFLAGS}