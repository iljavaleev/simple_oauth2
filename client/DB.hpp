#ifndef DB_hpp
#define DB_hpp

#include <vector>
#include <unordered_set>
#include <memory>
#include <format>

#include "crow.h"
#include <nlohmann/json.hpp>

#include <mongocxx/uri.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/client.hpp>

#include "Utils.hpp"


using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_array;
using bsoncxx::builder::basic::make_document;
 
inline mongocxx::instance instance{};


class DB
{
    mongocxx::uri uri;
    mongocxx::client client;
    mongocxx::database db;
    mongocxx::collection client_collection;
    mongocxx::collection token_collection;
    mongocxx::collection state_collection;
public:
    DB(const std::string _db = "auth")
    {
        uri = mongocxx::uri(std::format("mongodb://{}:{}", 
            std::getenv("CLIENT_MONGODB_HOST"),
            std::getenv("CLIENT_MONGODB_PORT")
        ));
        client = mongocxx::client(uri);
        db = client[_db]; 
        client_collection = db["client"];
        token_collection = db["server"];
        state_collection = db["state"];
    }
    mongocxx::collection get_client_collection() const 
    { 
        return client_collection; 
    }
    mongocxx::collection get_token_collection() const 
    { 
        return token_collection; 
    }
    mongocxx::collection get_state_collection() const 
    { 
        return state_collection; 
    }
};


struct ProtectedResource
{
    std::string uri;
    ProtectedResource(const std::string& _uri):uri(_uri){}
};


struct Server
{
    std::string authorization_endpoint;
    std::string token_endpoint;

    Server(
        const std::string& _auth, 
        const std::string& _token
        ):
        authorization_endpoint(_auth), token_endpoint(_token){}
};


struct State
{
    std::string state;
    std::string client_id;

    static std::shared_ptr<State> get(const Client& client);
    static std::shared_ptr<State> create(const Client& client);
};


struct Client
{
    std::string access_token;
    std::string refresh_token;
    
    std::string client_id;
    std::string client_secret;
    std::vector<std::string> redirect_uris;
    std::unordered_set<std::string> scopes;
    
    time_t client_id_created_at;
    time_t client_id_expires_at;
    std::string client_name;

    std::unordered_set<std::string> grant_types;
    std::unordered_set<std::string> response_types;
    std::string token_endpoint_auth_method;
    
    const static std::string client_uri;
    const static std::unordered_set<std::string> token_endpoint_auth_methods;

    void save();
    static std::shared_ptr<Client> get(); 
    static bool destroy(const std::string& client_id);
};

#endif
