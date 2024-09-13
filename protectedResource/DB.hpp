#ifndef DB_hpp
#define DB_hpp

#include <vector>
#include <unordered_set>
#include <memory>

#include <crow.h>
#include <nlohmann/json.hpp>

#include <mongocxx/uri.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/client.hpp>


using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_array;
using bsoncxx::builder::basic::make_document;
 
inline mongocxx::instance instance{};


struct Token
{
    std::string token;
    std::string client_id;
    std::string expire; 
    std::unordered_set<std::string> scope;
    Token(
        const std::string& _token, 
        const std::string& _client_id,
        const std::string& _expire,
        const std::unordered_set<std::string>& _scope
    ):
    token(_token), client_id(_client_id), expire(_expire), scope(_scope){}
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
        uri = mongocxx::uri("mongodb://localhost:27017");
        client = mongocxx::client(uri);
        db = client[_db]; 
        collection = db[_coll];
    }
    mongocxx::collection get_collection() { return collection; }
    static std::shared_ptr<Token> get(const std::string& token);
};


#endif