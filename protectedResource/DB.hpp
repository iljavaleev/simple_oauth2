#ifndef DB_hpp
#define DB_hpp

#include <crow.h>
#include <nlohmann/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/string/to_string.hpp>

#include <mongocxx/uri.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/stdx.hpp>
#include <mongocxx/client.hpp>

#include <vector>
#include <optional>
#include <unordered_set>
#include <optional>

using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_array;
using bsoncxx::builder::basic::make_document;
 
inline mongocxx::instance instance{};

class Auth
{
    mongocxx::uri uri;
    mongocxx::client client;
    mongocxx::database db;
    mongocxx::collection collection;
public:
    Auth(const std::string _db = "auth", const std::string _coll = "server")
    {
        uri = mongocxx::uri("mongodb://localhost:27017");
        client = mongocxx::client(uri);
        db = client[_db]; 
        collection = db[_coll];
    }
    bool token_exists(const std::string& token);
    std::unordered_set<std::string> get_scope(const std::string&);
};


#endif