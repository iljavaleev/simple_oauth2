FROM ubuntu:latest

WORKDIR /usr/src/client
COPY . .
    
RUN apt-get update -y \
    && apt-get install -y clang binutils \
    && apt-get install curl \
    && apt-get install nlohmann-json3-dev \
    && apt-get install -y build-essential cmake libboost-system-dev libssl-dev zlib1g-dev libcurl4-openssl-dev git

RUN git clone https://github.com/libcpr/cpr.git \
    && cd cpr && mkdir build && cd build \
    && cmake .. -DCPR_USE_SYSTEM_CURL=ON -DBUILD_SHARED_LIBS=OFF \
    && cmake --build . --parallel \
    && cmake --install . \
    && cd /usr/src/client

RUN curl -OL https://github.com/mongodb/mongo-cxx-driver/releases/download/r3.10.1/mongo-cxx-driver-r3.10.1.tar.gz \
    && tar -xzf mongo-cxx-driver-r3.10.1.tar.gz \
    && cd mongo-cxx-driver-r3.10.1/build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release -DMONGOCXX_OVERRIDE_DEFAULT_INSTALL_PREFIX=OFF  \
    && cmake --build . \
    && cmake --build . --target install \
    && cd /usr/src/client

RUN mkdir build \
    && cd build \
    && cmake .. \
    && make \
    && chmod +x ./client

CMD ["/usr/src/authServer/build/client"]