# generic dockerfile
FROM ubuntu:latest
    
RUN apt-get update -y \
    && apt-get install -y clang binutils \
    && apt-get install curl \
    && apt-get install nlohmann-json3-dev \
    && apt-get install -y libmongoc-1.0 build-essential cmake libboost-system-dev libssl-dev zlib1g-dev libcurl4-openssl-dev git

RUN curl -OL https://github.com/mongodb/mongo-cxx-driver/releases/download/r3.10.1/mongo-cxx-driver-r3.10.1.tar.gz \
    && tar -xzf mongo-cxx-driver-r3.10.1.tar.gz \
    && cd mongo-cxx-driver-r3.10.1/build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release -DMONGOCXX_OVERRIDE_DEFAULT_INSTALL_PREFIX=OFF  \
    && cmake --build . \
    && cmake --build . --target install
