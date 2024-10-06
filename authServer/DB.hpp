#ifndef DB_hpp
#define DB_hpp

#include "crow.h"
#include <vector>
#include <unordered_set>
#include <memory>
#include <format>

#include "Utils.hpp"
#include <nlohmann/json.hpp>

#include <mongocxx/uri.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/client.hpp>


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
    mongocxx::collection code_collection;
    mongocxx::collection request_collection;
public:
    DB(const std::string _db = "auth")
    {
        uri = mongocxx::uri(std::format("mongodb://{}:{}", 
            std::getenv("MONGODB_HOST"),
            std::getenv("MONGODB_PORT")
        ));
        client = mongocxx::client(uri);
        db = client[_db]; 
        client_collection = db["client"];
        token_collection = db["server"];
        code_collection = db["code"];
        request_collection = db["request"];
    }
    mongocxx::collection get_client_collection() const 
    { 
        return client_collection; 
    }
    mongocxx::collection get_token_collection() const 
    { 
        return token_collection; 
    }
    mongocxx::collection get_code_collection() const 
    { 
        return code_collection; 
    }
    mongocxx::collection get_request_collection() const 
    { 
        return request_collection; 
    }
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


struct Request
{
    std::string req_id;
    std::string query;
    Request(
        const std::string& _req_id, 
        const std::string& _query
        ):
        req_id(_req_id), query(_query){}
    void create();
    static std::shared_ptr<Request> get(const std::string& req_id); 
    static bool destroy(const std::string& req_id);
};


struct Client
{
    std::string client_id;
    std::string client_secret;
    std::vector<std::string> redirect_uris;
    std::unordered_set<std::string> scopes;
    Client(
        const std::string& _id,
        const std::string& _secret,
        std::vector<std::string> _redirect_uris, 
        std::unordered_set<std::string> _scopes):
        client_id(_id), 
        client_secret(_secret), 
        redirect_uris(_redirect_uris),
        scopes(_scopes){}
    Client(
        const std::string& _id,
        const std::string& _secret,
        std::vector<std::string> _redirect_uris, 
        std::string _scopes):
        client_id(_id), 
        client_secret(_secret), 
        redirect_uris(_redirect_uris)
        {   
            scopes = std::unordered_set<std::string>(get_scopes(_scopes));
        }
    void create();
    static std::shared_ptr<Client> get(const std::string& client_id); 
    static bool destroy(const std::string& client_id);
    static std::vector<std::shared_ptr<Client>> get_all();
};


struct ProtectedResource
{
    std::string resource_id;
    std::string resource_uri;
    ProtectedResource(const std::string& id, const std::string& uri):
        resource_id(id), resource_uri(uri){}
};


struct Code
{
    std::string code;
    std::string query;
    std::unordered_set<std::string> scopes;
    Code(
        const std::string& _code,
        const std::string& _query, 
        const std::unordered_set<std::string> _scopes):
        code(_code), query(_query), scopes(_scopes){}
    
    void create();
    static std::shared_ptr<Code> get(const std::string& code);
    static bool destroy(const std::string& code);
};


struct Token
{
    std::string token;
    std::string client_id;
    time_t expire; 
    std::unordered_set<std::string> scopes;
    Token(
        const std::string& _token, 
        const std::string& _client_id,
        time_t _expire,
        const std::unordered_set<std::string> _scopes):
    token(_token), 
    client_id(_client_id), 
    expire(_expire), 
    scopes(_scopes){}
 
    void create();
    
    static void create(
        const std::string& token,
        const std::string& client_id, 
        std::time_t exp,
        std::unordered_set<std::string> scopes
    );
    
    static std::shared_ptr<Token> get(const std::string& token, 
        const std::string& type);
    static bool destroy(const std::string& client_id, const std::string& type);
    static bool destroy_all(const std::string& client_id);
};

#endif
