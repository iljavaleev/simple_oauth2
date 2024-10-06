
#include "Utils.hpp"

#include <cpr/cpr.h>
#include "crow.h"
#include <nlohmann/json.hpp>
#include "DB.hpp"
#include <format>

using json = nlohmann::json;
const std::string SERVER_URI = std::format(
    "{}:{}", std::getenv("SERVER"), std::getenv("SERVER_PORT"));

std::string get_public_key(
    const ProtectedResource& resource
)
{
    std::string credits{crow::utility::base64encode(
        resource.resource_id, 
        resource.resource_id.size())}; 
    json j = {{"resource", credits}};
    
    cpr::Response r = cpr::Post(
        cpr::Url{SERVER_URI + "/public_key"}, 
        cpr::Header{{"Content-Type", "application/json"}},
        cpr::Body{j.dump()});
    
    if (r.status_code >= 200 && r.status_code < 300)
    {
        json response = json::parse(r.text);
        return response["public_key"];
    }
    return std::string();
}


jwt::verifier<jwt::default_clock, jwt::traits::kazuho_picojson> get_verifier(
    const std::string& pk)
{
    return jwt::verify().
        with_type("JWT").
        allow_algorithm(jwt::algorithm::rs256(pk, "", "", ""));
}


void send_error(crow::response& resp, std::string&& message, int code)
{
    resp.code = code;
    json j = {{ "error", message }};
    resp.body = j.dump();
}