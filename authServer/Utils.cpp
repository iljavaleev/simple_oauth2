#include "Utils.hpp"

#include <sstream>
#include <iostream>
#include <string>
#include <curl/curl.h>
#include <unordered_set>
#include <string>
#include <fstream>
#include <sstream>

#include "crow.h"
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>


using nlohmann::json;


const std::string WORKDIR = std::getenv("WORKDIR");


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
    return ss.str();
}


std::vector<std::string> decode_client_credentials(
    const std::string& code)
{
    std::string token = code.substr(code.find(' ') + 1);
    size_t pos = token.find(':');
    if(pos == token.npos)
        return  {};
    std::string id{token.substr(0, pos)}, 
        secret{token.substr(pos+1)};
    
    std::string decode_token = crow::utility::base64decode(token, token.size());
    
    return { crow::utility::base64decode(id, id.size()), 
        crow::utility::base64decode(secret, secret.size()) };
}


std::unordered_map<std::string, std::string> parse_form_data(std::string form)
{
    std::unordered_map<std::string, std::string> res;
    char pair_del = '&';
    char map_del = '=';
    std::vector<std::string> pairs;
    
    std::size_t stop{}; 
    std::string pair;
    while ((stop = form.find(pair_del)) != form.npos)
    {   
        pairs.emplace_back(form.substr(0, stop));
        form = form.substr(++stop);
    }
    
    
    pairs.emplace_back(form);
    std::string key, value;
    for (auto p: pairs)
    {
        stop = p.find(map_del);
        res.insert({p.substr(0, stop), p.substr(stop + 1)});    
    }
    return res;
}

crow::response send_error(std::string&& message, int code)
{
    crow::response resp;
    resp.code = code;
    json j = { "error", message };
    resp.body =  j.dump();
    return resp;
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


std::unordered_set<std::string> get_scopes(const std::string& scopes)
{
    std::unordered_set<std::string> res;
    std::istringstream iss(scopes);
    std::string s;
    while (getline(iss, s, ' ')) 
        res.insert(s);
    return res;
}


std::string get_scopes(const std::unordered_set<std::string>& scopes)
{
    std::ostringstream ss;
    for (const auto& s: scopes)
        ss << s << " ";
    std::string res = ss.str();
    res.pop_back();
    return res;
}

jwt::verifier<jwt::default_clock, jwt::traits::kazuho_picojson> get_verifier()
{
    std::ifstream public_key(WORKDIR + "/public.pem");
    std::stringstream buffer;

    buffer << public_key.rdbuf();
    std::string pbk{buffer.str()};
    buffer.clear();

    return jwt::verify().with_type("JWT").
            allow_algorithm(
        jwt::algorithm::rs256(pbk, "", "", ""));
}
