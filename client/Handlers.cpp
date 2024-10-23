#include "Handlers.hpp"

#include <format>

#include "inja.hpp"
#include <nlohmann/json.hpp>

#include "Utils.hpp"
#include "DB.hpp"

using json = nlohmann::json;
using Client = models::Client;
using Server = models::Server;
using State = models::State;

inja::Environment env;
const std::string WORKDIR = std::getenv("WORKDIR");
inja::Template error_temp = env.parse_template(WORKDIR + "/files/error.html");
inja::Template data_temp = env.parse_template(WORKDIR + "/files/data.html");
inja::Template index_temp = env.parse_template(WORKDIR + "/files/index.html");
inja::Template client_info_temp = 
    env.parse_template(WORKDIR + "/files/client_info.html");


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
    json render_json, client_json;
    client_json = client;
    render_json["access_token"] = !client.access_token.empty() ? 
        client.access_token : "NONE";
    render_json["refresh_token"] = !client.refresh_token.empty() ? 
        client.refresh_token : "NONE";
    render_json["scope"] = !client.scope.empty() ? 
        get_scope(client.scope) : "NONE";
    render_json["client"] = client_json;
    std::string res = env.render(index_temp, render_json);
    auto page = crow::mustache::compile(res);
    return page.render();
}


crow::response authorize::operator()(const crow::request& req) const
{
    crow::response res;
    json jres;
    if (client.client_id.empty())
    {
        register_client(client);
        if (client.client_id.empty())
        {
            jres["error"] = "Unable to register client";
            res.body = jres.dump();
            res.code = 400;
            return res;
        }
    }
    auto state = State::create(client);
    json options = {
        {"response_type", "code"},
        {"client_uri", Client::client_uri},
        {"scope", !client.scope.empty() ? 
            get_scope(client.scope) : "foo bar"},
	    {"client_id", client.client_id},
		{"redirect_uri", client.redirect_uris.at(0)},
		{"state", state->state}
    };

    std::string uri = build_url(server.authorization_endpoint, options);
    res.redirect(uri);
    return res;
}


crow::mustache::rendered_template callback::operator()(
    const crow::request& req) const
{
    
    json render_json;
    std::string res, state;
    state = State::get(client)->state;
    
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
        client, token_endpoint, std::string(code)
    );
    
    inja::Template templ;
	if (!try_get)
    {
        render_json["error"] = "Unable to fetch access token";
        templ = error_temp;
    }
    else
    {
        json jclient = client;
        render_json = {
            {"access_token", client.access_token},
            {"refresh_token", !client.refresh_token.empty() ? 
                client.refresh_token : "None"},
            {"scope", get_scope(client.scope)},
            {"client", jclient }
        };
        client.save();
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
        CROW_LOG_WARNING << "access token problem";
        if(refresh_token(client, server.token_endpoint))
        {
            response = get_answer(client, protected_resource);
            if(response.contains("error") && response["error"] < 500)
            {
                client.refresh_token.clear();                
                client.save();
            }
        }    
    }

    if (response.contains("error"))
    {   
        CROW_LOG_WARNING << "refresh token problem";
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
        client.scope.clear();
        client.save();
        json render_json, jclient = client;
        render_json["access_token"] = !client.access_token.empty() ? 
            client.access_token : "NONE";
        render_json["refresh_token"] = !client.refresh_token.empty() ? 
            client.refresh_token : "NONE";
        render_json["scope"] = !client.scope.empty() ? 
            get_scope(client.scope) : "NONE";
        render_json["client"] = jclient;
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
        client.save();
        json render_json, jclient = client;
        render_json["access_token"] = !client.access_token.empty() ? 
            client.access_token : "NONE";
        render_json["refresh_token"] = !client.refresh_token.empty() ? 
            client.refresh_token : "NONE";
        render_json["scope"] = !client.scope.empty() ? 
            get_scope(client.scope) : "NONE";
        render_json["client"] = jclient;
        res = env.render(index_temp, render_json);
    }
    else
    {
        res = env.render(error_temp, {{"error", "Code not found"}});
    }
    auto page = crow::mustache::compile(res);
    return page.render();
}


crow::mustache::rendered_template read_client::operator()(
    const crow::request&) const
{
    json response = get_client_info(client);
    std::string res;
    
    if (response.contains("error"))
    {
        res = env.render(error_temp, response);
    }
    else
    {
        res = env.render(client_info_temp, response);
        client.client_secret = response["client"]["client_secret"];
        client.registration_access_token = 
            response["client"]["registration_access_token"];
        client.save();
    }
    auto page = crow::mustache::compile(res);
    return page.render();
}


crow::mustache::rendered_template update_client::operator()(
    const crow::request& req) const
{
    std::string res;
    auto form_data = parse_form_data(req.body);
    try
    {
        client.client_name = form_data.at("client_name");
        replace_char_by_space(client.client_name, '+');
    }
    catch(const std::exception& e)
    {
        CROW_LOG_WARNING << e.what();
        res = env.render(error_temp, e.what());
        auto page = crow::mustache::compile(res);
        return page.render();
    }
    
    json response = update_client_info(client);
    if (response.contains("error"))
    {
        res = env.render(error_temp, response);
    }
    else
    {
        res = env.render(index_temp, response);
    }

    auto page = crow::mustache::compile(res);
    return page.render();
}


crow::mustache::rendered_template delete_client::operator()(
    const crow::request&) const
{
    json response = delete_client_request(client);
    std::string res;
    
    if (response.contains("error"))
    {
        res = env.render(error_temp, response);
    }
    else
    {
        res = env.render(index_temp, response);
    }
    auto page = crow::mustache::compile(res);
    return page.render();
}