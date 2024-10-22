#ifndef Utils_hpp
#define Utils_hpp

#include <sstream>
#include <unordered_set>

#include <nlohmann/json.hpp>

using json = nlohmann::json;
namespace models
{
    struct Client;
}
using Client = models::Client;

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
json get_client_info(const Client& client);
json update_client_info(Client& client);
json delete_client_request(const Client& client);
std::unordered_set<std::string> get_scope(const std::string& query);
std::string get_scope(const std::unordered_set<std::string>& scope);
std::string decode_str(const std::string& encoded);
std::string encode_str(const std::string& decoded);
unsigned int revoke_token(Client& client, std::string&& type);
std::unordered_map<std::string, std::string> parse_form_data(std::string form);
void replace_char_by_space(std::string&, char); 

#endif
