ARG TAG=v1
FROM valeevilja/simple_oauth2:${TAG}

WORKDIR /usr/src/oauth2
COPY . .

RUN git clone https://github.com/libcpr/cpr.git \
    && cd cpr && mkdir build && cd build \
    && cmake .. -DCPR_USE_SYSTEM_CURL=ON -DBUILD_SHARED_LIBS=OFF \
    && cmake --build . --parallel \
    && cmake --install . \
    && cd ${WORKDIR}


RUN git clone https://github.com/Thalhammer/jwt-cpp.git \
    && cd jwt-cpp \
    && cmake . \
    && cmake --build . \
    && cmake --install . \
    && ${WORKDIR}

    
RUN mkdir build \
    && cd build \
    && cmake .. \
    && make \
    && chmod +x ./res

CMD ["/usr/src/oauth2/build/res"]