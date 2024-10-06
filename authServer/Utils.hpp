#ifndef Utils_hpp
#define Utils_hpp
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <nlohmann/json.hpp>
#include "crow.h"
#include <jwt-cpp/jwt.h>

std::string gen_random(const int len);
std::string build_url(std::string base, nlohmann::json options);
std::string encode_client_credentials(
    const std::string client_id,  
    const std::string client_secret);
std::vector<std::string> decode_client_credentials( const std::string& code);
std::unordered_map<std::string, std::string> parse_form_data(std::string form);
crow::response send_error(std::string&& message, int code);
std::string url_decode(const std::string& encoded);
std::string url_encode(const std::string& decoded);
std::unordered_set<std::string> get_scopes(const std::string& query);
std::string get_scopes(const std::unordered_set<std::string>& scopes);
jwt::verifier<jwt::default_clock, jwt::traits::kazuho_picojson> get_verifier();
#endif
