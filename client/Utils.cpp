
#include "Utils.hpp"

#include <ctime>
#include <iostream>
#include <unistd.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <cpr/cpr.h>
#include <stdexcept>
#include "DB.hpp"

using json = nlohmann::json;


std::string gen_random(const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) {
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    
    return tmp_s;
}

std::string build_url(std::string base, nlohmann::json options)
{
    std::ostringstream url;
    url << base << '?';
    for (json::iterator it = options.begin(); it != options.end(); ++it) 
    {
        url << it.key() << '=' << it.value().template get<std::string>() << "&";
    }
    std::string uri = url.str();
    uri.pop_back();
    return uri;

}

std::string encode_client_credentials(
    const std::string client_id,  
    const std::string client_secret)
{
    std::ostringstream ss;
    ss << crow::utility::base64encode(client_id, client_id.size()) << ':';
    ss << crow::utility::base64encode(client_secret, client_secret.size());
    std::cout << ss.str() << std::endl;
    return ss.str();
}

bool get_token(
    Client& client, 
    const std::string& uri, 
    const std::string& code
)
{
    bool ret{false};
    cpr::Response r = cpr::Post(
        cpr::Url{uri}, 
        cpr::Header{
            {"Content-Type", "application/x-www-form-urlencoded"}, 
            {"Authorization", "Basic " + 
                encode_client_credentials(
                    client.client_id, client.client_secret)}},
        cpr::Payload{
            {"grant_type", "authorization_code"},
            {"code", code},
            {"redirect_uri", client.redirect_uris.at(0)}});
    
    
    if (r.status_code >= 200 && r.status_code < 300)
    {
        json response = json::parse(r.text);
        client.access_token = response["access_token"];
        if(response.contains("refresh_token"))
            client.refresh_token = response["refresh_token"];
        client.scopes = get_scopes(response["scope"].dump());
        ret = true;
    }
    return ret;
}

bool refresh_token(
    Client& client, 
    const std::string& uri
)
{
    bool ret{false};

    cpr::Response token_response = cpr::Post(
        cpr::Url{uri},
        cpr::Header{
            {"Content-Type", "application/x-www-form-urlencoded"}, 
            {"Authorization", "Basic " + 
            encode_client_credentials(client.client_id, client.client_secret)}},
        cpr::Payload{
            {"grant_type", "refresh_token"},
            {"refresh_token", client.refresh_token}}
    );
    
    if (token_response.status_code >= 200 && 
        token_response.status_code < 300)
    {
        json response = json::parse(token_response.text);
        client.access_token = response["access_token"];
        if(response.contains("refresh_token"))
            client.refresh_token = response["refresh_token"];
        client.scopes = get_scopes(response["scope"].dump());
        ret = true;
    }    
    return ret;
}

json get_answer(const Client& client, const std::string& uri)
{
    cpr::Response r = cpr::Post(
        cpr::Url{uri}, 
        cpr::Header{{"Authorization", "Bearer " + client.access_token}});
    json response;
    if (r.status_code >= 200 && r.status_code < 300)
        response = json::parse(r.text);    
    return response;
}

std::unordered_set<std::string> get_scopes(const std::string& query)
{
    std::unordered_set<std::string> res;
    std::istringstream iss(url_decode(query));
    std::string s;
    while (getline(iss, s, ' ')) 
        res.insert(s);
    return res;
}

std::string get_scopes(const std::unordered_set<std::string>& scopes)
{
    std::ostringstream ss;
    for (const auto& s: scopes)
        ss << s << ' ';
    return ss.str();
}

std::string url_encode(const std::string& decoded)
{
    const auto encoded_value = curl_easy_escape(
        nullptr, decoded.c_str(), static_cast<int>(decoded.length()));
    std::string result(encoded_value);
    curl_free(encoded_value);
    return result;
}

std::string url_decode(const std::string& encoded)
{
    int output_length;
    const auto decoded_value = curl_easy_unescape(
        nullptr, 
        encoded.c_str(), 
        static_cast<int>(encoded.length()), 
        &output_length);
    std::string result(decoded_value, output_length);
    curl_free(decoded_value);
    return result;
}

