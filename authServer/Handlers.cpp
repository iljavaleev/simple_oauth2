#include "Handlers.hpp"

#include "crow.h"
#include <memory>
#include <algorithm>
#include <unordered_map>
#include <string>
#include <vector>
#include <format>
#include <fstream>

#include "DB.hpp"
#include "Utils.hpp"
#include "ClientMetadataMW.hpp"

#include "inja.hpp"
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>


using json = nlohmann::json;
using namespace models;

inja::Environment env;
const std::string WORKDIR = std::getenv("WORKDIR");
const std::string server_uri = std::format("{}:{}", 
	std::getenv("SERVER"), std::getenv("SERVER_PORT"));
inja::Template index_temp = env.parse_template(WORKDIR + "/files/index.html");
inja::Template appr_temp = env.parse_template(WORKDIR + "/files/approve.html");
inja::Template error_temp = env.parse_template(WORKDIR + "/files/error.html");


ProtectedResource resource(
    "resource_id",
    std::format(
		"http://{}:{}", 
		std::getenv("RESOURCE"), 
		std::getenv("RESOURCE_PORT"))
);


crow::mustache::rendered_template idx::operator()(
	const crow::request& req) const
{
	std::vector<std::shared_ptr<Client>> clients = Client::get_all();
	json render_json;
	std::vector<json> res_json;

	for (auto& cl: clients)
	{
		json client_json = *cl;
		res_json.push_back(client_json);
	}
	render_json["clients"] = res_json;
	render_json["auth_server"] = {
		{"authorization_endpoint", server_uri + "/authorize"}, 
		{"token_endpoint", server_uri + "/token"}
	};
	std::string res = env.render(index_temp, render_json);
	auto page = crow::mustache::compile(res);
	return page.render();
}


crow::mustache::rendered_template authorize::operator()(
	const crow::request& req) const
{
	char* client_id_p = req.url_params.get("client_id");
    std::string res;
	if (!client_id_p)
	{	
		res = env.render(error_temp, {{"error", "Unknown client"}});
		auto page = crow::mustache::compile(res);
		return page.render();
	}
    
    std::string client_id{client_id_p};
    std::shared_ptr<Client> client = Client::get(client_id);
    if(!client)
	{
		res = env.render(error_temp, {{"error", "Unknown client"}});
		auto page = crow::mustache::compile(res);
		return page.render();
	}
    
    std::vector r_uris = client->redirect_uris;
    
    if (!req.url_params.get("redirect_uri") || 
        std::find(r_uris.begin(), r_uris.end(), 
        std::string(req.url_params.get("redirect_uri"))) == r_uris.end())
    {
        res = env.render(error_temp, {{"error", "Invalid redirect URI"}});
		auto page = crow::mustache::compile(res);
		return page.render();
    }   
	
	if (!req.url_params.get("scope"))
	{
		res = env.render(error_temp, {{"error", "Scope not found"}});
		auto page = crow::mustache::compile(res);
		return page.render();
	}
	
	auto scope = get_scope(req.url_params.get("scope"));
	for (const auto& el: scope)
	{
		if(!client->scope.contains(el))
		{	
			res = env.render(error_temp, {{"error", "invalid scope"}});
			auto page = crow::mustache::compile(res);
			return page.render();
		}
	}
	    
	crow::query_string query = req.url_params;
    const std::string reqid = gen_random(8);
    
	Request request(reqid, req.raw_url);
	request.create();
	
	std::vector<std::string> client_scope;
	client_scope.insert(
		client_scope.end(), 
		client->scope.begin(), 
		client->scope.end()
	);
    
	json render_json;
	render_json["scope"] = client_scope;
	render_json["reqid"] = reqid;
	
	res = env.render(appr_temp, render_json);
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
    
	std::unordered_set<std::string> scope;
	std::string sc;
	for (const auto& p: form)
	{
		if (p.first.find("scope_") != p.first.npos)
		{
			sc = p.first.substr(p.first.find("_") + 1);
			scope.insert(sc);
		}
	}
	
	std::string client_id{query.get("client_id")};
    std::shared_ptr<Client> client = Client::get(client_id);
	std::string url_parsed;
	if (!client)
	{
		url_parsed = build_url(query.get("redirect_uri"), 
				{{ "error", "denied access"}});
		resp.redirect(url_parsed);
		return resp;
	}
	
	if(scope.empty())
	{
		url_parsed = build_url(query.get("redirect_uri"), 
				{{ "error", "denied access"}});
		resp.redirect(url_parsed);
		return resp;
	}
	
	for (const auto& el: scope)
	{
		if(!client->scope.contains(el))
		{
			url_parsed = build_url(query.get("redirect_uri"), 
				{{ "error", "invalid scope"}});
			resp.redirect(url_parsed);
			return resp;
		}
	}
	
	if ((form.contains("approve") && form.at("approve").empty()) || 
		form.contains("deny"))
	{
		url_parsed = build_url(query.get("redirect_uri"), 
            {{ "error", "access_denied"}});
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
	
	std::string code = gen_random(12);
	Code code_inst(code, request->query, scope);
	
	code_inst.create();
    
    url_parsed = build_url(query.get("redirect_uri"), 
		{{ "code", code }, { "state", query.get("state") }});
	
	resp.redirect_perm(url_parsed);
    return resp;
}


crow::response token::operator()(const crow::request& req) const
{
    crow::response resp;
	std::string client_id, client_secret;
	
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
	
	if (!body.contains("grant_type") || 
		!(body.at("grant_type") == "authorization_code" ||
		body.at("grant_type") == "refresh_token")) 
		return send_error("unsupported_grant_type", 400);

	
	std::unordered_set<std::string> scope;
	if (body.at("grant_type") == "authorization_code")
	{
		if (!body.contains("code"))
			return send_error("invalid_grant", 400);
		
		std::shared_ptr<Code> cod = Code::get(body.at("code"));
		if (!cod)
			return send_error("invalid_grant", 400);
		scope = cod->scope;
		Code::destroy(body.at("code"));
		crow::query_string query(cod->query);	

		if (query.get("client_id") != client_id)
			return send_error("invalid_grant", 400);
	}
	else if (body.at("grant_type") == "refresh_token")
	{
		if (!body.contains("refresh_token"))
			return send_error("invalid_grant", 400);
		
		try
		{
			get_verifier().verify(jwt::decode(body.at("refresh_token")));
		}
		catch(const std::exception& e)
		{
			CROW_LOG_WARNING << "wrong refresh token"; 
			return send_error("invalid_grant", 400);
		}
		
		auto old_token = 
			Token::get(body.at("refresh_token"), "refresh_token");

		if (!old_token || old_token->client_id != client_id)
		{
			CROW_LOG_WARNING << "refresh token db problem"; 
			Token::destroy(body.at("refresh_token"), "refresh_token");
			return send_error("invalid_grant", 400);
		}

		scope = old_token->scope;
	}
	const auto now = std::chrono::system_clock::now();
	const auto exp = now + std::chrono::days(10);
    std::ifstream private_key(WORKDIR + "/key.pem");
    std::stringstream buffer;
    
    buffer << private_key.rdbuf();
    std::string prk{buffer.str()};
    buffer.clear();
    
    using namespace std::literals; 
    const std::time_t expire = std::chrono::system_clock::to_time_t(exp);
    auto access_token = jwt::create()
		.set_type("JWT")
		.set_algorithm("RS256")
		.set_issuer(server_uri)
		.set_audience(resource.resource_uri)
		.set_payload_claim("expire", 
			jwt::claim(std::to_string(expire)))
		.set_payload_claim("scope", 
			jwt::claim(std::string(get_scope(scope))))
		.set_id("authserver")
		.sign(jwt::algorithm::rs256("", prk, "", ""));

	auto refresh_token = jwt::create()
		.set_type("JWT")
		.set_algorithm("RS256")
		.sign(jwt::algorithm::rs256("", prk, "", ""));
	
	
	Token::create(access_token, client_id, expire, scope);
	Token::create(refresh_token, client_id, 0, scope);
	
	json res_resp = { 
		{"access_token", access_token}, 
		{"token_type", "Bearer"},
		{"access_token expire", std::format("{:%Y%m%d%H%M}", exp)},
		{"refresh_token", refresh_token },
		{ "scope", get_scope(scope) } 
	};
	
	resp.code = 200;
	resp.body = res_resp.dump();
	return resp;
}


crow::response public_key::operator()(const crow::request& req) const
{
	crow::response resp;
	json body, jresp;
	try
	{
		body = json::parse(req.body);
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		resp.code = 400;
		return resp;
	}
	
	if (!body.contains("resource") || 
		crow::utility::base64decode(body["resource"]) != resource.resource_id)
	{
		resp.code = 400;
		return resp;
	}

	std::ifstream public_key(WORKDIR + "/public.pem");
    std::stringstream buffer;
	buffer << public_key.rdbuf();
    std::string pbk{buffer.str()};

	jresp["public_key"] = std::move(pbk);
	resp.code = 200;
	resp.body = jresp.dump();
	return resp;
}


crow::response revoke_handler::operator()(const crow::request& req) const
{
	crow::response resp;
	std::string client_id, client_secret;
	
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
	
	std::string token{body["token"]}, type{body["type"]};
	std::shared_ptr<Token> token_inst = Token::get(token, body["type"]);
	
	if (token_inst || token_inst->client_id == client_id)
	{
		if (type == "access_token")
			Token::destroy(client_id, type);
		else
			Token::destroy_all(client_id);
	}
	resp.code = 204;
	return resp;
}


crow::response register_handler::operator()(const crow::request& req) const
{
	const auto& ctx = app.get_context<ClientMetadataMW>(req);
	models::Client new_client = ctx.new_client;
	
    new_client.client_id = gen_random(12);
	new_client.client_id_created_at = 
		std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    new_client.client_id_expires_at = 0;


	if(models::Client::token_endpoint_auth_methods.contains(
        new_client.token_endpoint_auth_method))
	{
		new_client.client_secret = gen_random(16);
	}

	new_client.registration_access_token = gen_random(12);
	new_client.registration_client_uri = std::format(
		"http://{}:{}/register/{}", 
		std::getenv("SERVER"), 
		std::getenv("SERVER_PORT"), 
		new_client.client_id);
	
	crow::response resp;
	json body = new_client;
	new_client.save();
	
	resp.code = 201;
	resp.body = body.dump(4);
	return resp;
}

crow::response client_management_handler::operator()(
	const crow::request& req, std::string&& client_d) const
{
	crow::response resp;
	const auto& ctx = app.get_context<AuthorizeConfigurationMW>(req);
	models::Client client = ctx.req_client;

	if (req.method == crow::HTTPMethod::GET)
	{
		
		client.client_secret = gen_random(12);
		client.registration_access_token = gen_random(16);
		client.save();
		
		json jresp = client;
		resp.body = jresp.dump(4);
	}
	else if (req.method == crow::HTTPMethod::PUT)
	{
		json body = json::parse(req.body);

		bool client_id_varif = body.contains("client_id") && 
			(body["client_id"].template get<std::string>() 
				== client.client_id);
		bool client_secret_varif = body.contains("client_secret") && 
			(body["client_secret"].template get<std::string>() 
				== client.client_secret);
		
		if (!(client_id_varif && client_secret_varif))
		{
			CROW_LOG_WARNING << "PUT; client varification error";
			send_error("invalid_client_metadata", 400);
		}
		
		const auto& client_mdata_ctx = app.get_context<ClientMetadataMW>(req);
		models::Client result_client, req_client{client_mdata_ctx.new_client};
		
		result_client.client_id = client.client_id;
		result_client.client_secret = client.client_secret;
		result_client.client_id_created_at = client.client_id_created_at;
		result_client.client_id_expires_at = client.client_id_expires_at;
		result_client.registration_access_token = 
			client.registration_access_token;
		result_client.registration_client_uri = client.registration_client_uri;
		
		result_client.token_endpoint_auth_method = 
			req_client.token_endpoint_auth_method;
		result_client.redirect_uris = req_client.redirect_uris;
		result_client.client_uri = req_client.client_uri;
		result_client.scope = req_client.scope;
		result_client.grant_types = req_client.grant_types;
		result_client.response_types = req_client.response_types;
		result_client.client_name = req_client.client_name;
		
		result_client.save();
		
		json jresp = result_client;
		resp.body = jresp.dump();
		resp.code = 200;
	}
	else if (req.method == crow::HTTPMethod::DELETE)
	{
		try
		{
			Token::destroy_all(client.client_id);
			models::Client::destroy(client.client_id);
		}
		catch(const std::exception& e)
		{
			CROW_LOG_WARNING << e.what();
		}
		resp.code = 204;
	}
    return resp;
}
