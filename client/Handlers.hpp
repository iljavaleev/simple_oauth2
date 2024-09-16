#ifndef Handlers_hpp
#define Handlers_hpp

#include <string>
#include <memory>

#include "crow.h"
#include <nlohmann/json.hpp>
#include "DB.hpp"


struct idx{
    Client client;
    idx(const Client& _client): client(_client){}
    
    crow::mustache::rendered_template operator()(
        const crow::request& req) const;
};

struct authorize{
    Client client;
    Server server;
    authorize(
        const Client& _client, 
        const Server& _server): 
        client(_client), server(_server){}
    
    crow::response operator()(
        const crow::request& req) const;
};

struct callback{
    Client& client;
    Server& server;
    callback(
        Client& _client, 
        Server& _server): 
        client(_client), server(_server){}
    crow::mustache::rendered_template operator()(const crow::request&) const;
};

struct fetch_resource{
    Client& client;
    Server& server;
    fetch_resource(
        Client& _client, 
        Server& _server): 
        client(_client), server(_server){}
    crow::mustache::rendered_template operator()(const crow::request&) const;
};


#endif
