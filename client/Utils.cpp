
#include "Utils.hpp"

#include <iostream>
#include <sstream>
#include <format>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include "DB.hpp"


using json = nlohmann::json;
using Client = models::Client;
using Server = models::Server;

const std::string server_uri = std::format(
    "http://{}:{}", std::getenv("SERVER"), std::getenv("SERVER_PORT"));

const std::string client_internal_uri = std::format(
    "http://{}:{}", 
    std::getenv("CLIENT_INTERNAL"), 
    std::getenv("CLIENT_PORT_INTERNAL")
);


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
        client.scope = get_scope(
            response["scope"].template get<std::string>());
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
        cpr::Url{server_uri + "/token"},
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
        client.scope = get_scope(
            response["scope"].template get<std::string>());
        ret = true;
    }    
    return ret;
}


void register_client(Client& client)
{   
    json j = {
        {"client_name", "Test name"},
        {"client_uri", client_internal_uri},
        {"redirect_uris", {client_internal_uri + "/callback"}},
        {"grant_types", {"authorization_code"}},
        {"response_types", {"code"}},
        {"scope", "foo bar"},
        {"token_endpoint_auth_method", "secret_basic"}
    };
    
    cpr::Response r = cpr::Post(
        cpr::Url{server_uri + "/register"}, 
        cpr::Header{
            {"Content-Type", "application/json"}, 
            {"Accept", "application/json"}
        },
        cpr::Body{j.dump()});
    
    
    if (r.status_code >= 200 && r.status_code < 300)
    {   
        json response;
        try
        {
            response = json::parse(r.text);
        }
        catch(const std::exception& e)
        {
            CROW_LOG_WARNING << "error parsing register response";
        }
        client.client_id = response["client_id"];
        if (response.contains("client_secret"))
            client.client_secret = response["client_secret"];
        client.token_endpoint_auth_method = 
            response["token_endpoint_auth_method"];
        client.client_id_created_at = response["client_id_created_at"];
        client.client_id_expires_at = response["client_id_expires_at"];
        client.registration_client_uri = 
            response["registration_client_uri"];
        client.registration_access_token = 
            response["registration_access_token"];
        client.grant_types = response["grant_types"].
            template get<std::unordered_set<std::string>>();
        client.response_types = response["response_types"].
            template get<std::unordered_set<std::string>>();
        client.redirect_uris = response["redirect_uris"].
            template get<std::vector<std::string>>();
        if (response.contains("client_name"))
		    client.client_name  = response["client_name"];
        if (response.contains("scope"))
        {
            client.scope = response["scope"].template get<std::unordered_set<std::string>>();
        }
    
        try
        {
            client.save();
        }
        catch(const std::exception& e)
        {
            CROW_LOG_WARNING << "error saving client";
        }
    }
}


unsigned int revoke_token(
    Client& client, 
    std::string&& type
)
{   
    std::string token = type == "access_token" ? 
        client.access_token : client.refresh_token;
    cpr::Response revoke_response = cpr::Post(
        cpr::Url{server_uri + "/revoke"},
        cpr::Header{
            {"Content-Type", "application/x-www-form-urlencoded"}, 
            {"Authorization", "Basic " + 
            encode_client_credentials(client.client_id, client.client_secret)}},
        cpr::Payload{{"token", token}, {"type", type}}
    );
    
   return revoke_response.status_code;
}


json get_answer(const Client& client, const std::string& uri)
{
    cpr::Response r = cpr::Post(
        cpr::Url{uri}, 
        cpr::Header{{"Authorization", "Bearer " + client.access_token}});
    
    json response;
    if (r.status_code >= 200 && r.status_code < 300)
        response = json::parse(r.text);
    else
        response["error"] = r.status_code;
   
    return response;
}


json get_client_info(const Client& client)
{
    cpr::Response r = cpr::Get(
        cpr::Url{client.registration_client_uri},
        cpr::Header{
            {"Accept", "application/json"},
            {"Authorization", "Bearer " + client.registration_access_token}
        });
    if (r.status_code == 200)
        return {{"client", json::parse(r.text)}};
    
    return {{"error", 
        std::format("Unable to read client {}", r.status_code)}};
}


json update_client_info(Client& client)
{
    json request = client;
    request["client_uri"] = Client::client_uri;
    request.erase("client_id_issued_at");
    request.erase("client_secret_expires_at");
    request.erase("registration_client_uri");
    request.erase("registration_access_token");
    request.erase("access_token");
    request.erase("refresh_token");
    cpr::Response r = cpr::Put(
        cpr::Url{client.registration_client_uri},
        cpr::Header{
            {"Content-Type", "application/json"},
            {"Accept", "application/json"},
            {"Authorization", "Bearer " + client.registration_access_token}
        },
        cpr::Body{request.dump()}
    );
    Client res_client;
    if (r.status_code == 200)
    {
        res_client = json::parse(r.text).template get<Client>();
        client.client_secret = res_client.client_secret;
        client.redirect_uris = res_client.redirect_uris;
        client.scope = res_client.scope;
        client.client_name = res_client.client_name;
        client.grant_types = res_client.grant_types;
        client.response_types = res_client.response_types;
        client.token_endpoint_auth_method = 
            res_client.token_endpoint_auth_method;
        client.save();

        return {
            {"client", json::parse(r.text)},
            {"access_token", client.access_token},
            {"refresh_token", client.refresh_token},
            {"scope", get_scope(client.scope)}
        };
    }
    return {{"error", 
        std::format("Unable to read client {}", r.status_code)}};
}


json delete_client_request(Client& client)
{
    cpr::Response r = cpr::Delete(
        cpr::Url{client.registration_client_uri},
        cpr::Header{
            {"Authorization", "Bearer " + client.registration_access_token}
        }
    );
    Client::destroy(client.client_id);
    Client new_client;
    client = new_client;
    json j_client = client;
    if (r.status_code == 204)
    {
        return {
            {"client", j_client},
            {"access_token", "None"},
            {"refresh_token", "None"},
            {"scope", "None"}
        };
    }
    return {{"error", 
        std::format("Unable to delete client {}", r.status_code)}};
}


std::unordered_set<std::string> get_scope(const std::string& scope)
{
    std::unordered_set<std::string> res;
    std::istringstream iss(scope);
    std::string s;
    while (getline(iss, s, ' ')) 
        res.insert(s);
    return res;
}


std::string get_scope(const std::unordered_set<std::string>& scope)
{
    std::ostringstream ss;
    for (const auto& s: scope)
        ss << s << " ";
    std::string res = ss.str();
    res.pop_back();
    return res;
}


std::string encode_str(const std::string& decoded)
{
    const auto encoded_value = curl_easy_escape(
        nullptr, decoded.c_str(), static_cast<int>(decoded.length()));
    std::string result(encoded_value);
    curl_free(encoded_value);
    return result;
}

std::string decode_str(const std::string& encoded)
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

void replace_char_by_space(std::string& str, char target)
{
    int i;
    while((i = str.find(target)) != str.npos)
        str.at(i) = ' ';
} 
