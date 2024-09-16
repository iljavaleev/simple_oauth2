ARG TAG=v1
FROM valeevilja/simple_oauth2:${TAG}

WORKDIR /usr/src/oauth2
COPY . .

RUN git clone https://github.com/libcpr/cpr.git \
    && cd cpr && mkdir build && cd build \
    && cmake .. -DCPR_USE_SYSTEM_CURL=ON -DBUILD_SHARED_LIBS=OFF \
    && cmake --build . --parallel \
    && cmake --install . \
    && cd /usr/src/oauth2

RUN mkdir build \
    && cd build \
    && cmake .. \
    && make \
    && chmod +x ./client

CMD ["/usr/src/oauth2/build/client"]