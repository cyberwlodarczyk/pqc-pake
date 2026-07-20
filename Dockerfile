ARG UBUNTU_VERSION=24.04
ARG PQC_PAKE_DIR=/opt/pqc-pake
ARG CFLAGS="-I${PQC_PAKE_DIR}/include"
ARG LDFLAGS="-L${PQC_PAKE_DIR}/lib -Wl,-rpath,${PQC_PAKE_DIR}/lib"

FROM ubuntu:${UBUNTU_VERSION} AS build
ARG PQC_PAKE_DIR
ARG CFLAGS
ARG LDFLAGS
RUN apt-get update
RUN apt-get -y install gcc cmake libssl-dev
WORKDIR /pqc-pake
COPY src/ ./src/
WORKDIR /pqc-pake/build
ENV PQC_PAKE_DIR=${PQC_PAKE_DIR}
RUN cmake ../src
RUN make
RUN make install

FROM ubuntu:${UBUNTU_VERSION} AS dev
ARG PQC_PAKE_DIR
ARG CFLAGS
ARG LDFLAGS
RUN apt-get update
RUN apt-get -y install gcc cmake libssl-dev git python3 python3-matplotlib
COPY --from=build ${PQC_PAKE_DIR} ${PQC_PAKE_DIR}
ENV PQC_PAKE_DIR=${PQC_PAKE_DIR}
ENV CFLAGS=${CFLAGS}
ENV LDFLAGS=${LDFLAGS}