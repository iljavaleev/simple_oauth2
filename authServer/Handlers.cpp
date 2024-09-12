#include "Handlers.hpp"
#include "Utils.hpp"
#include <nlohmann/json.hpp>
#include "DB.hpp"
#include <memory>
#include <algorithm>
#include "Utils.hpp"
#include <unordered_map>
#include <string>
#include "crow.h"
#include <utility>
#include <cpr/cpr.h>
#include <format>
#include <inja/inja.hpp>

using json = nlohmann::json;


crow::mustache::rendered_template authorize::operator()(const crow::request& req) const
{
    auto err_page = crow::mustache::load("error.html");
    char* client_id_p = req.url_params.get("client_id");
    if (!client_id_p)
        return err_page.render({{"error", "Unknown client"}});
    
    std::string client_id{client_id_p};
    std::shared_ptr<Client> client = Client::get(client_id);
    if(!client)
       return err_page.render({{"error", "Unknown client"}});
    std::vector r_uris = client->redirect_uris;
    
    if (!req.url_params.get("redirect_uri") || 
        std::find(r_uris.begin(), r_uris.end(), 
        std::string(req.url_params.get("redirect_uri"))) == r_uris.end())
    {
        return err_page.render({{"error", "Invalid redirect URI"}});
    }   
	// scope 
	if (!req.url_params.get("scope"))
		return err_page.render({{"error", "Scope not found"}});
	
	// check scope eq
	auto scopes = get_scopes(req.url_params.get("scope"));
	for (const auto& el: scopes)
	{
		if(!client->scopes.contains(el))
			return err_page.render({{"error", "invalid scope"}});

	}
	    
	// save query
	crow::query_string query = req.url_params;
    const std::string reqid = gen_random(8);
    
	Request request(reqid, req.raw_url);
	request.create();
	
	// render
	std::vector<std::string> client_scopes;
	client_scopes.insert(
		client_scopes.end(), 
		client->scopes.begin(), 
		client->scopes.end()
	);
    
	json render_json;
	render_json["scopes"] = client_scopes;
	render_json["reqid"] = reqid;
	
	inja::Environment env;
	inja::Template temp = env.parse_template("../files/approve.html");
	std::string res = env.render(temp, render_json);
	auto page = crow::mustache::compile(res);
	return page.render();
}


crow::response approve::operator()(const crow::request& req) const
{
	crow::response resp;
	std::unordered_map <std::string, std::string> form = 
        parse_form_data(req.body);
	
    if (!form.contains("reqid"))
        return send_error("No matching authorization request", 403);

    std::string reqid = form.at("reqid");
    
	std::shared_ptr<Request> request = Request::get(reqid);
	if (!request)  
        return send_error("No matching authorization request", 403);

	crow::query_string query(request->query);
    Request::destroy(reqid);
    
	std::unordered_set<std::string> scopes;
	std::string scope;
	for (const auto& p: form)
	{
		if (p.first.find("scope_") != p.first.npos)
		{
			scope = p.first.substr(p.first.find("_") + 1);
			scopes.insert(scope);
		}
	}
	
	std::string client_id{query.get("client_id")};
    std::shared_ptr<Client> client = Client::get(client_id);
	std::string url_parsed;

	// check subset
	for (const auto& el: scopes)
	{
		if(!client->scopes.contains(el))
		{
			url_parsed = build_url(query.get("redirect_uri"), 
				{ "error", "invalid scope"});
			resp.redirect(url_parsed);
			return resp;
		}
	}

	if (form.at("approve").empty())
	{
		url_parsed = build_url(query.get("redirect_uri"), 
            { "error", "access_denied"});
		resp.redirect(url_parsed);
		return resp;
	}
	
	if (strcmp(query.get("response_type"), "code") != 0) 
	{	
		url_parsed = build_url(query.get("redirect_uri"), 
            {{ "error", "unsupported_response_type"}});
		resp.redirect(url_parsed);
		return resp;
	} 
	
	std::string code = gen_random(8);
	Code code_inst(code, request->query, scopes);
	code_inst.create();
    
	try
    {
        url_parsed = build_url(query.get("redirect_uri"), // check for keys
            {{ "code", code }, { "state", query.get("state") }});
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        url_parsed = build_url(query.get("redirect_uri"), 
            {{ "error",  e.what()}});
		resp.redirect(url_parsed);
		return resp;
    }
	resp.redirect_perm(url_parsed);
    return resp;
}

crow::response token::operator()(const crow::request& req) const
{
    crow::response resp;
	std::string client_id, client_secret;
	
	// headers
	auto auth_it = req.headers.find("authorization");
    if (auth_it != req.headers.end())
	{
		std::string auth = auth_it->second;
		std::vector<std::string> client_credentials = 
			decode_client_credentials(auth);
		if (client_credentials.empty())
			return send_error("invalid_client", 401);
		client_id = client_credentials.at(0);
		client_secret = client_credentials.at(1);
	}
	
	auto body = parse_form_data(req.body);
	if(body.contains("client_id"))
	{
		if (!client_id.empty())
			return send_error("invalid_client", 401);
		client_id = body["client_id"];
		client_secret = body["client_secret"];
	}
	
	auto client = Client::get(client_id);
	if (!client || client->client_secret != client_secret) 
		return send_error("invalid_client", 401);
	
	// authorization grant request
	if (!body.contains("grant_type") || 
		!(body.at("grant_type") == "authorization_code" ||
		body.at("grant_type") == "refresh_token")) 
		return send_error("unsupported_grant_type", 400);

	std::shared_ptr<Code> cod;
	if (body.at("grant_type") == "authorization_code")
	{
		if (!body.contains("code"))
			return send_error("invalid_grant", 400);
		
		cod = Code::get(body.at("code"));
		if (!cod)
			return send_error("invalid_grant", 400);
		
		Code::destroy(body.at("code"));
		crow::query_string query(cod->query);	

		if (query.get("client_id") != client_id)
			return send_error("invalid_grant", 400);
	}
	else if (body.at("grant_type") == "refresh_token")
	{
		auto body = parse_form_data(req.body);
		if (!body.contains("refresh_token"))
			return send_error("invalid_grant", 400);
		
		std::string old_client_id = 
			Token::get_client(body.at("refresh_token"), TokenType::refresh);

		if (old_client_id.empty() || old_client_id != client_id)
		{
			Token::destroy(body.at("refresh_token"), TokenType::refresh);
			return send_error("invalid_grant", 400);
		}
		else
			Token::destroy_all(client_id);
	}
	std::string access_token = gen_random(16);
	std::string refresh_token = gen_random(16);
	Token acs_token(access_token, client_id, cod->scopes, TokenType::access);
	std::shared_ptr<std::string> exp = acs_token.create();
	Token rfr_token(refresh_token, client_id, cod->scopes, TokenType::refresh);
	rfr_token.create();
	json res_resp = { 
		{"access_token", access_token}, 
		{"token_type", "Bearer"},
		{"access_token expire", *exp },
		{"refresh_token", refresh_token },
		{ "scope", get_scopes(cod->scopes) } 
	};
	resp.code = 200;
	resp.body = res_resp.dump();
	return resp;
    
}