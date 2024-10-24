#ifndef DB_hpp
#define DB_hpp

#include <vector>
#include <unordered_set>
#include <memory>
#include <format>

#include "crow.h"


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
    std::unordered_set<std::string> scope;
    Token(
        const std::string& _token, 
        const std::string& _client_id,
        time_t _expire,
        const std::unordered_set<std::string> _scope):
    token(_token), 
    client_id(_client_id), 
    expire(_expire), 
    scope(_scope){}
};

#endif
