#ifndef AuthMiddlware_hpp
#define AuthMiddlware_hpp

#include "crow.h"
#include <string>
#include <nlohmann/json.hpp>
#include "DB.hpp"
#include <unordered_set>


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

        Auth a;
        auto scope = a.get_scope(token);
        if(scope.empty())
        {
            res.code = 401;
            res.end();
            return;
        }
        ctx.token = token;
        ctx.scope = scope;
    }

    void after_handle(crow::request& req, crow::response& res, context& ctx){}
};

#endif