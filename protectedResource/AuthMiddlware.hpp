#ifndef AuthMiddlware_hpp
#define AuthMiddlware_hpp

#include <string>
#include <unordered_set>

#include "crow.h"
#include <nlohmann/json.hpp>
#include "DB.hpp"


using json = nlohmann::json;


struct AuthMW: crow::ILocalMiddleware
{
    struct context
    {
        std::string token{};
        std::unordered_set<std::string> scope;
    };

    void before_handle(crow::request& req, crow::response& res, context& ctx)
    {
        auto auth = req.headers.find("Authorization"); 
        if ((auth == req.headers.end()) && (auth->second.empty()))
        {   
            res.code = 403;
            res.end();
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

        auto token_inst = DB::get(token);

        json j_error;
        if(!token_inst)
        {
            res.code = 401;
            j_error  = {"error", "no such access token exists"};
            res.body = j_error.dump();
            res.end();
            return;
        }
        const long exp = std::stoll(token_inst->expire);
        const std::chrono::time_point now{std::chrono::system_clock::now()};
        const std::time_t t_c = std::chrono::system_clock::to_time_t(now);
        
        if (exp - t_c < 0)
        {
            res.code = 401;
            j_error  = {"error", "аccess token has expired"};
            res.body = j_error.dump();
            res.end();
            return;
        }

        std::unordered_set<std::string> possible_scopes{"foo", "bar"};
        for (const auto& s: token_inst->scope)
        {
            if (!possible_scopes.contains(s))
            {
                 res.code = 401;
                j_error  = {"error", "no such scope exists"};
                res.body = j_error.dump();
                res.end();
                return;
            }
        }

        ctx.token = token_inst->token;
        ctx.scope = token_inst->scope;
    }

    void after_handle(crow::request& req, crow::response& res, context& ctx){}
};

#endif