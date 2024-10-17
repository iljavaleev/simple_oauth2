#ifndef ClientMetadataMW_hpp
#define ClientMetadataMW_hpp

#include <string>
#include <unordered_set>

#include "crow.h"
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>
#include "DB.hpp"
#include "Utils.hpp"

using json = nlohmann::json;


struct ClientMetadataMW: crow::ILocalMiddleware
{
    struct context
    {
        models::Client new_client;
    };

    void before_handle(crow::request& req, crow::response& res, context& ctx)
    {
        if (req.raw_url.size() < 10 || req.method == crow::HTTPMethod::PUT)
        {
            json body;
            models::Client new_client;
            try
            {
                body = json::parse(req.body);
            }
            catch(const std::exception& e)
            {
                CROW_LOG_WARNING << e.what();
                res.end();
                return;
            }
            
            if (body.contains("token_endpoint_auth_method"))
                new_client.token_endpoint_auth_method = 
                    body["token_endpoint_auth_method"];
            else
                new_client.token_endpoint_auth_method = "secret_basic";
            
            if (!models::Client::token_endpoint_auth_methods.
                contains(new_client.token_endpoint_auth_method))
            {
                send_error(res, "invalid_client_metadata", 400);
                res.end();
                return;
            }
            
            std::unordered_set<std::string> gt, rt;
            if (body.contains("grant_types"))
            {
                gt = body["grant_types"].
                    template get<std::unordered_set<std::string>>();
            }
            
            if (body.contains("response_types"))
            {
                rt = body["response_types"].
                    template get<std::unordered_set<std::string>>();
            }

            if (body.contains("grant_types") && body.contains("response_types"))
            {
                new_client.grant_types = gt;
                new_client.response_types = rt;

                if (new_client.grant_types.contains("authorization_code") && 
                    !new_client.response_types.contains("code"))
                {
                    new_client.response_types.insert("code");
                }

                if (!new_client.grant_types.contains("authorization_code") && 
                    new_client.response_types.contains("code"))
                {
                    new_client.grant_types.insert("authorization_code");
                }
            }
            else if (body.contains("grant_types"))
            {
                new_client.grant_types = gt;
                
                if (new_client.grant_types.contains("authorization_code"))
                {
                    new_client.response_types.insert("code");
                }
            }
            else if (body.contains("response_types"))
            {
                new_client.response_types = rt;
                
                if (new_client.response_types.contains("code"))
                {
                    new_client.grant_types.insert("authorization_code");
                }
            }
            else
            {
                new_client.grant_types.insert("authorization_code");
                new_client.response_types.insert("code");
            }
            
            gt.erase("authorization_code");
            rt.erase("code");
            if (!gt.empty() || !rt.empty())
            {
                CROW_LOG_WARNING << "inv rt gt";
                send_error(res, "invalid_client_metadata", 400);
                res.end();
                return;
            }

            if (!body.contains("redirect_uris"))
            {
                CROW_LOG_WARNING << "redirect uri missed";
                send_error(res, "invalid_redirect_uri", 400);
                res.end();
                return;
            }	

            if (body["redirect_uris"].is_array())
                new_client.redirect_uris = 
                    body["redirect_uris"].
                    template get<std::vector<std::string>>();
            else
                new_client.redirect_uris.push_back(body["redirect_uris"]);
            
            if (new_client.redirect_uris.empty() || 
                new_client.redirect_uris.at(0).empty())
            {
                CROW_LOG_WARNING << "redirect uri missed";
                send_error(res, "invalid_redirect_uri", 400);
                res.end();
                return;
            }
            
            if (!body.contains("client_uri"))
            {
                CROW_LOG_WARNING << "client uri missed";
                send_error(res, "invalid_client_uri", 400);
                res.end();
                return;
            }	
            
            new_client.client_uri  = body["client_uri"];

            if (body["client_name"].is_string())
                new_client.client_name  = body["client_name"];
            
            if (body["scope"].is_string())
            {
                new_client.scopes = 
                    get_scopes(body["scope"].template get<std::string>());
            }
                    
            ctx.new_client = new_client;
        }    
    }

    void after_handle(crow::request& req, crow::response& res, context& ctx){}
};

#endif