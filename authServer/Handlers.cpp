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

#include "inja.hpp"
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>


using json = nlohmann::json;

inja::Environment env;
const std::string WORKDIR = std::getenv("WORKDIR");
inja::Template index_temp = env.parse_template(WORKDIR + "/files/index.html");
inja::Template appr_temp = env.parse_template(WORKDIR + "/files/approve.html");
inja::Template error_temp = env.parse_template(WORKDIR + "/files/error.html");

extern ProtectedResource resource;

crow::mustache::rendered_template idx::operator()(
	const crow::request& req) const
{
	std::vector<std::shared_ptr<Client>> clients = Client::get_all();
	json render_json;
	std::vector<json> res_json;

	for (const auto& cl: clients)
	{
		json client_json;
		client_json["client_id"] = cl->client_id;
		client_json["client_secret"] = cl->client_secret;
		client_json["scope"] = get_scopes(cl->scopes);
		client_json["redirect_uri"] = cl->redirect_uris.at(0);
		res_json.push_back(client_json);
	}
	render_json["clients"] = res_json;
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
	
	auto scopes = get_scopes(req.url_params.get("scope"));
	for (const auto& el: scopes)
	{
		if(!client->scopes.contains(el))
		{	
			res = env.render(error_temp, {{"error", "invalid scope"}});
			auto page = crow::mustache::compile(res);
			return page.render();
		}
	}
	    
	crow::query_string query = req.url_params;
	srand((unsigned)time(NULL) * getpid());
    const std::string reqid = gen_random(8);
    
	Request request(reqid, req.raw_url);
	request.create();
	
	std::vector<std::string> client_scopes;
	client_scopes.insert(
		client_scopes.end(), 
		client->scopes.begin(), 
		client->scopes.end()
	);
    
	json render_json;
	render_json["scopes"] = client_scopes;
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
	if (!client)
	{
		url_parsed = build_url(query.get("redirect_uri"), 
				{{ "error", "denied access"}});
		resp.redirect(url_parsed);
		return resp;
	}
	
	if(scopes.empty())
	{
		url_parsed = build_url(query.get("redirect_uri"), 
				{{ "error", "denied access"}});
		resp.redirect(url_parsed);
		return resp;
	}
	
	for (const auto& el: scopes)
	{
		if(!client->scopes.contains(el))
		{
			url_parsed = build_url(query.get("redirect_uri"), 
				{{ "error", "invalid scope"}});
			resp.redirect(url_parsed);
			return resp;
		}
	}
	
	if (form.at("approve").empty())
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
	srand((unsigned)time(NULL) * getpid());
	std::string code = gen_random(12);
	Code code_inst(code, request->query, scopes);
	
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

	
	std::unordered_set<std::string> scopes;
	if (body.at("grant_type") == "authorization_code")
	{
		if (!body.contains("code"))
			return send_error("invalid_grant", 400);
		
		std::shared_ptr<Code> cod = Code::get(body.at("code"));
		if (!cod)
			return send_error("invalid_grant", 400);
		scopes = cod->scopes;
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
			Token::destroy(body.at("refresh_token"), "refresh_token");
			return send_error("invalid_grant", 400);
		}

		scopes = old_token->scopes;
	}
	const auto now = std::chrono::system_clock::now();
	const auto exp = now + std::chrono::days(10);
    std::ifstream private_key(WORKDIR + "/key.pem");
    std::stringstream buffer;
    
    buffer << private_key.rdbuf();
    std::string prk{buffer.str()};
    buffer.clear();
    
    using namespace std::literals; 
    
    auto access_token = jwt::create().
		set_type("JWT").
		set_algorithm("RS256").
		set_issuer("http://localhost:9001/").
		set_audience("http://localhost:9002/").
		set_id("authserver").
		sign(jwt::algorithm::rs256("", prk, "", ""));

	auto refresh_token = jwt::create().
		set_type("JWT").
		set_algorithm("RS256").
		sign(jwt::algorithm::rs256("", prk, "", ""));
	
	const std::time_t expire = std::chrono::system_clock::to_time_t(exp);
	Token::create(access_token, client_id, expire, scopes);
	Token::create(refresh_token, client_id, 0, scopes);
	
	json res_resp = { 
		{"access_token", access_token}, 
		{"token_type", "Bearer"},
		{"access_token expire", std::format("{:%Y%m%d%H%M}", exp)},
		{"refresh_token", refresh_token },
		{ "scope", get_scopes(scopes) } 
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


crow::response register::operator()(const crow::request& req) const
{
	Client new_client;
	json body, jresp;
	crow::response resp;
	try
	{
		body = json::parse(req.body);
	}
	catch(const std::exception& e)
	{
		CROW_LOG_WARNING << e;
		resp.code = 400;
		return resp;
	}

	if (body.contains["token_endpoint_auth_method"])
	{
		new_client.token_endpoint_auth_method = 
			body["token_endpoint_auth_method"];
	}
	else
	{
		new_client.token_endpoint_auth_method = "secret_basic";
		body["token_endpoint_auth_method"] = "secret_basic";
	}
	
	if (!Client::token_endpoint_auth_methods.
		contains(new_client.token_endpoint_auth_method))
	{
		return send_error("invalid_client_metadata", 400);
	}

	std::unordered_set<std::string> gt = 
		body.contains["grant_types"] ? body["grant_types"].
			template get<std::unordered_set<std::string>>() : {};

	std::unordered_set<std::string> rt = 
		body.contains["response_types"] ? body["response_types"].
			template get<std::unordered_set<std::string>>() : {};


	if (body.contains["grant_types"] && body.contains["response_types"])
	{
		new_client.grant_types{gt};
		new_client.response_types{rt}

		if (new_client.grant_types.conatins("authorization_code") && 
			!new_client.response_types.conatins("code"))
		{
			new_client.response_types.insert("code");
			body["response_types"].push_back("code");
		}

		if (!new_client.grant_types.conatins("authorization_code") && 
			new_client.response_types.conatins("code"))
		{
			new_client.grant_types.insert("authorization_code");
			body["grant_types"].push_back("authorization_code");
		}
	}
	else if (body.contains["grant_types"])
	{
		new_client.grant_types{gt};
		
		if (new_client.grant_types.conatins("authorization_code"))
		{
			new_client.response_types.insert("code");
			body["response_types"].push_back("code");
		}
	}
	else if (body.contains["response_types"])
	{
		new_client.response_types{rt};
		
		if (new_client.response_types.conatins("code"))
		{
			new_client.grant_types.insert("authorization_code");
			body["grant_types"].push_back("authorization_code");
		}
	}
	else
	{
		new_client.grant_types.insert("authorization_code");
		body["grant_types"].push_back("authorization_code");
		
		new_client.response_types.insert("code");
		body["response_types"].push_back("code");
	}

	if (!gt.extract("authorization_code").empty() || 
		!rt.extract("code").empty())
	{
		CROW_LOG_WARNING << "inv rt gt";
		return send_error("invalid_client_metadata", 400);
	}

	if (!body.contains("redirect_uris"))
	{
		CROW_LOG_WARNING << "redirect uri missed";
		return send_error("invalid_redirect_uri", 400);
	}	

	if (body["redirect_uris"].is_array())
		new_client.redirect_uris = 
			body["redirect_uris"].template get<std::vector<std::string>>()
	else
		new_client.redirect_uris.push_back(body["redirect_uris"]);
	
	if (new_client.redirect_uris.empty() || 
		new_client.redirect_uris.at(0).empty())
	{
		CROW_LOG_WARNING << "redirect uri missed";
		return send_error("invalid_redirect_uri", 400);
	}

	if (body["client_name"].is_string())
		new_client.client_name  = body["client_name"];

	if (body["client_uri"].is_string())
		new_client.client_name  = body["client_uri"];

	if (body["scope"].is_string())
		new_client.client_name  = get_scopes(body["scope"]);

	new_client.client_id_created_at(
		std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())
	);
	body["client_id_created_at"] = new_client.client_id_created_at;
	new_client.client_id_expires_at = 0;
	body["client_id_expires_at"] = new_client.client_id_expires_at;
	srand((unsigned)time(NULL) * getpid());
	new_client->client_id = gen_random(12);
	body["client_id"] = new_client->client_id; 
	if(Client::token_endpoint_auth_methods.contains(
		new_client.token_endpoint_auth_method))
	{
		srand((unsigned)time(NULL) * getpid());
		new_client.client_secret = gen_random(16);
		body["client_secret"] = new_client->client_secret; 
	}
	new_client.create();
	resp.code(201);
	resp.body = body.dump(4);
	return resp;
}
