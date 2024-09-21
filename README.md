# simple_oauth2

## Simple implementation of OAuth2 protocol inspired by book OAuth 2 in Action (Justin Richer (Author), Antonio Sanso).
The code was completely rewritten in C++, using MongoDB as the NoSQL database. HTML templates remained almost unchanged.

### Description
There are three parts that interact with each other: the client (abstract application), the authentication server and protected resource.
The client redirects the user to the authentication server to gain access to the resource
The user decides whether to grant access permission to client and to what extent(scope). 
Next comes gaining access(receiving a token) and the ability to request data from the resource.

All three parts in different docker containers.

## Run application
### Run with Cmake
For example for client:
```
cd client
mkdir build && cd build
cmake ..
make
./client 
```
You need to export envs from .cmake.env
### Run  with docker compose
In infra path execute
```
docker compose --env-file .env -f docker-compose.yml up -d
```
There is image in docker hub for each part. If you want to build localy you can use generic Dockerfile in the infra path.

Next you need to go to the http://localhost:9000 endpoint in the browser.