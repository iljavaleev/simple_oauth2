ARG TAG=v1
FROM valeevilja/simple_oauth2:${TAG}

WORKDIR /usr/src/oauth2
COPY . .
    
RUN mkdir build \
    && cd build \
    && cmake .. \
    && make \
    && chmod +x ./auth

CMD ["/usr/src/oauth2/build/auth"]