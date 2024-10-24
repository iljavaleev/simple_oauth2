#ifndef AuthMiddlware_hpp
#define AuthMiddlware_hpp

#include <string>
#include <unordered_set>

#include "crow.h"
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>
#include "DB.hpp"
#include "Utils.hpp"

using json = nlohmann::json;

inline ProtectedResource resource("resource_id", "http://localhost:9002");

struct AuthMW: crow::ILocalMiddleware
{
    struct context
    {
        std::unordered_set<std::string> scope;
    };

    void before_handle(crow::request& req, crow::response& res, context& ctx)
    {
        auto auth = req.headers.find("Authorization"); 
        if ((auth == req.headers.end()) && (auth->second.empty()))
        {   
            res.code = 403;
            res.end();
            return;
        }
        std::string authorization = auth->second;
        std::string token;

        std::string bearer = authorization.substr(0, authorization.find(' '));
        for (char& c: bearer)
            c = tolower(c);
        if (bearer == "bearer")
        {
            token = authorization.substr(authorization.find(' ') + 1);
        }
        else
        {
            json body = json::parse(req.body);
            if(!body.empty() && body.contains("access_token"))
            {
                token = body["access_token"].dump();
            }
            else
            {
                auto t = req.url_params.get("access_token");
                if (t)
                    token = std::string(t);
            }
        }
        
        if (token.empty())
        {
            send_error(res, "no token privided", 401);
            res.end();
            return;
        }

        json j_error;
        std::string pk = get_public_key(resource);
        if (pk.empty())
        {
            send_error(res, "validation error", 500);
            res.end();
            return;
        }  
        
        try
        {
           get_verifier(pk).verify(jwt::decode(token));
        }
        catch(const std::exception& e)
        {
            CROW_LOG_WARNING << "wrong token "; 
            send_error(res, "no such access token exists", 401);
            res.end();
            return;
        }
        
        json token_inst = parse_token_info(token);

        const std::time_t exp = std::stol(
            token_inst["expire"].template get<std::string>());

        const std::chrono::time_point now{std::chrono::system_clock::now()};
        const std::time_t t_c = std::chrono::system_clock::to_time_t(now);
        
        if (exp - t_c < 0)
        {   
            send_error(res, "аccess token has expired", 401);
            res.end();
            return; 
        }
            
        std::unordered_set<std::string> possible_scope{"foo", "bar"}, 
            token_scope{get_scope(token_inst["scope"])};
        for (const auto& s: token_scope)
            if (!possible_scope.contains(s))
            {
                send_error(res, "no such scope exists", 401);
                res.end();
                return;
            }
            
        ctx.scope = token_scope;
    }

    void after_handle(crow::request& req, crow::response& res, context& ctx){}
};

#endif