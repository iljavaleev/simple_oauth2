#ifndef Utils_hpp
#define Utils_hpp

#include <sstream>
#include <unordered_set>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct Client;
std::string gen_random(const int len);
std::string build_url(std::string base, nlohmann::json options);
std::string encode_client_credentials(
    const std::string client_id,  
    const std::string client_secret);
bool get_token(
    Client& client, 
    const std::string& uri, 
    const std::string& code
);
bool refresh_token(Client& client, const std::string& uri);
void register_client(Client& client);
json get_answer(const Client& client, const std::string& uri);
std::unordered_set<std::string> get_scopes(const std::string& query);
std::string get_scopes(const std::unordered_set<std::string>& scopes);
std::string url_decode(const std::string& encoded);
std::string url_encode(const std::string& decoded);
unsigned int revoke_token(Client& client, std::string&& type);

#endif
