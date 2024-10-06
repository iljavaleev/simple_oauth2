#ifndef Utils_hpp
#define Utils_hpp

#include <string>

#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>
#include "DB.hpp"


using json = nlohmann::json;

std::string get_public_key(const ProtectedResource& resource);
jwt::verifier<jwt::default_clock, jwt::traits::kazuho_picojson> get_verifier(
    const std::string& pk);
void send_error(crow::response& res, std::string&& message, int code);
#endif
