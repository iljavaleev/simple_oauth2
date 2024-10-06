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


using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_array;
using bsoncxx::builder::basic::make_document;
 
inline mongocxx::instance instance{};


struct ProtectedResource
{
    std::string resource_id;
    std::string resource_uri;
    ProtectedResource(const std::string& id, const std::string& uri):
        resource_id(id), resource_uri(uri){}
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
};


class DB
{
    mongocxx::uri uri;
    mongocxx::client client;
    mongocxx::database db;
    mongocxx::collection collection;
public:
    DB(const std::string _db = "auth", const std::string _coll = "server")
    {   
        uri = mongocxx::uri(std::format("mongodb://{}:{}", 
            std::getenv("MONGODB_HOST"),
            std::getenv("MONGODB_PORT")
        ));
        client = mongocxx::client(uri);
        db = client[_db]; 
        collection = db[_coll];
    }
    mongocxx::collection get_collection() { return collection; }
    static std::shared_ptr<Token> get(const std::string& token);
};


#endif
