#include "Handlers.hpp"

#include <format>

#include "inja.hpp"
#include <nlohmann/json.hpp>

#include "Utils.hpp"
#include "DB.hpp"

using json = nlohmann::json;

inja::Environment env;
const std::string WORKDIR = std::getenv("WORKDIR");
inja::Template error_temp = env.parse_template(WORKDIR + "/files/error.html");
inja::Template data_temp = env.parse_template(WORKDIR + "/files/data.html");
inja::Template index_temp = env.parse_template(WORKDIR + "/files/index.html");

std::string state{};


const std::string protected_resource = std::format(
    "http://{}:{}/resource", 
    std::getenv("RESOURCE"), 
    std::getenv("RESOURCE_PORT")
);
const std::string token_endpoint = std::format(
    "http://{}:{}/token", 
    std::getenv("SERVER"), 
    std::getenv("SERVER_PORT")
);


crow::mustache::rendered_template idx::operator()(
    const crow::request& req) const
{
    
    json render_json;
    render_json["access_token"] = !client.access_token.empty() ? 
        client.access_token : "NONE";
    render_json["refresh_token"] = !client.refresh_token.empty() ? 
        client.refresh_token : "NONE";
    render_json["scope"] = !client.scopes.empty() ? 
        get_scopes(client.scopes) : "NONE";
    
    std::string res = env.render(index_temp, render_json);
    auto page = crow::mustache::compile(res);
    return page.render();
}


crow::response authorize::operator()(const crow::request& req) const
{
    srand((unsigned)time(NULL) * getpid());
    state = gen_random(12);
    json options = {
        {"response_type", "code"},
        {"scope", get_scopes(client.scopes)},
	    {"client_id", client.client_id},
		{"redirect_uri", client.redirect_uris.at(0)},
		{"state", state}
    };
    std::string uri = build_url(server.authorization_endpoint, options);
    crow::response res;
    res.redirect(uri);
    return res;
}


crow::mustache::rendered_template callback::operator()(
    const crow::request& req) const
{
    
    json render_json;
    std::string res;
    if (req.url_params.get("error"))
    {
        res = env.render(error_temp, {{"error", req.url_params.get("error")}});
        auto page = crow::mustache::compile(res);
        return page.render();
    }

    if (!req.url_params.get("state") || req.url_params.get("state") != state)
    {
        res = env.render(error_temp, {{"error", "State not found"}});
        auto page = crow::mustache::compile(res);
        return page.render();
    }

    auto code = req.url_params.get("code");
    if (!code)
    {
        res = env.render(error_temp, {{"error", "Code not found"}});
        auto page = crow::mustache::compile(res);
        return page.render();
    }
    bool try_get = get_token(
        client, token_endpoint, std::string(code));
    
    inja::Template templ;
	if (!try_get)
    {
        render_json["error"] = "Unable to fetch access token";
        templ = error_temp;
    }
    else
    {
        render_json = {
            {"access_token", client.access_token},
            {"refresh_token", !client.refresh_token.empty() ? 
                client.refresh_token : "None"},
            {"scope", get_scopes(client.scopes)}
        };
        templ = index_temp;
    }
	res = env.render(templ, render_json);
	auto page = crow::mustache::compile(res);
    return page.render();
}


crow::mustache::rendered_template fetch_resource::operator()(
    const crow::request& req) const
{
    json render_json;
    std::string res;

    json response = get_answer(client, protected_resource);
    if (response.contains("error") && response["error"] < 500)
    {  
        client.access_token.clear();
        Token::destroy(client.client_id, "access_token");
        if(refresh_token(client, server.token_endpoint))
        {
            response = get_answer(client, protected_resource);
            if(response.contains("error") && response["error"] < 500)
            {
                client.refresh_token.clear();                
                Token::destroy_all(client.client_id);
            }
        }    
    }

    if (response.contains("error"))
    {   
        res = env.render(error_temp, {{"error", "Unable to fetch data."}});
        auto page = crow::mustache::compile(res);
        return page.render();
    }
    render_json["resource"] = response.dump(4);
    res = env.render(data_temp, render_json);
    auto page = crow::mustache::compile(res);
    return page.render();
}


crow::mustache::rendered_template revoke_handler::operator()(
    const crow::request& req) const
{
    std::string res;
    unsigned int status = revoke_token(client, "access_token");
    if (status >= 200 && status < 300)
    {
        client.access_token.clear();
        client.scopes.clear();
        json render_json;
        render_json["access_token"] = !client.access_token.empty() ? 
            client.access_token : "NONE";
        render_json["refresh_token"] = !client.refresh_token.empty() ? 
            client.refresh_token : "NONE";
        render_json["scope"] = !client.scopes.empty() ? 
            get_scopes(client.scopes) : "NONE";
        res = env.render(index_temp, render_json);
    }
    else
    {
        res = env.render(error_temp, {{"error", "Code not found"}});
    }
    auto page = crow::mustache::compile(res);
    return page.render();
}


crow::mustache::rendered_template revoke_refresh_handler::operator()(
    const crow::request& req) const
{
    std::string res;
    unsigned int status = revoke_token(client, "refresh_token");
    if (status >= 200 && status < 300)
    {
        client.access_token.clear();
        client.refresh_token.clear();
        json render_json;
        render_json["access_token"] = !client.access_token.empty() ? 
            client.access_token : "NONE";
        render_json["refresh_token"] = !client.refresh_token.empty() ? 
            client.refresh_token : "NONE";
        render_json["scope"] = !client.scopes.empty() ? 
            get_scopes(client.scopes) : "NONE";
        res = env.render(index_temp, render_json);
    }
    else
    {
        res = env.render(error_temp, {{"error", "Code not found"}});
    }
    auto page = crow::mustache::compile(res);
    return page.render();
}
