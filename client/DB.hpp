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



struct Client
{
    std::string client_id;
    std::string client_secret;
    std::vector<std::string> redirect_uris;
    std::unordered_set<std::string> scopes;

    std::string access_token{};
    std::string refresh_token{};

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
};


enum class TokenType { access, refresh };

struct Token
{
    std::string token;
    std::string client_id;
    std::string expire; 
    std::unordered_set<std::string> scopes;
    TokenType type;
    Token(
        const std::string& _token, 
        const std::string& _client_id,
        const std::string& expire,
        const std::unordered_set<std::string>& _scopes,
        TokenType _type):
    token(_token), client_id(_client_id), scopes(_scopes), type(_type){}

    static std::shared_ptr<Token> get(const std::string& token, TokenType type);
    
    static bool destroy(const std::string& client_id, TokenType type);
    static bool destroy_all(const std::string& client_id);
};

#endif