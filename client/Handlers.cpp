#include "Handlers.hpp"


#include "inja.hpp"
#include <nlohmann/json.hpp>

#include "Utils.hpp"
#include "DB.hpp"

using json = nlohmann::json;

inja::Environment env;
inja::Template error_temp = env.parse_template("../files/error.html");
inja::Template data_temp = env.parse_template("../files/data.html");
inja::Template index_temp = env.parse_template("../files/index.html");

std::string state{};
std::string protected_resource = "http://localhost:9002/resource";


crow::mustache::rendered_template idx::operator()(const crow::request& req) const
{
    std::shared_ptr<Token> acc_token = 
        Token::get(client.client_id, TokenType::access);
    std::shared_ptr<Token> refr_token = 
        Token::get(client.client_id, TokenType::refresh);
    
    json render_json;
  
    render_json["access_token"] = acc_token ? acc_token->token : "NONE";
    render_json["refresh_token"] = refr_token ? refr_token->token : "NONE";
    render_json["scope"] = acc_token ? get_scopes(acc_token->scopes) : "NONE";
    
    std::string res = env.render(index_temp, render_json);
    auto page = crow::mustache::compile(res);
    return page.render();
}

crow::response authorize::operator()(const crow::request& req) const
{
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

    bool try_get = get_token(client, server.token_endpoint, std::string(code));
    
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
    std::string tamlate_path, res;

    if(client.access_token.empty())
    {
        res = env.render(error_temp, {{"error", "Missing access token."}});
        auto page = crow::mustache::compile(res);
        return page.render();
    }
    
    json response = get_answer(client, protected_resource);
    if (response.contains("error") && response["error"] < 500)
    {  
        client.access_token = "";
        if(refresh_token(client, server.token_endpoint))
        {
            response = get_answer(client, protected_resource);
            if(response.contains("error") && response["error"] < 500)
                client.refresh_token = "";
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
