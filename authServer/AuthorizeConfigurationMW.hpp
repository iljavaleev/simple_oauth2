#ifndef AuthorizeConfigurationMW_hpp
#define AuthorizeConfigurationMW_hpp

#include <string>
#include <unordered_set>
#include "memory"

#include "crow.h"
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>
#include "DB.hpp"
#include "Utils.hpp"


using json = nlohmann::json;


struct AuthorizeConfigurationMW: crow::ILocalMiddleware
{
    struct context
    {
        models::Client req_client;
    };

    void before_handle(crow::request& req, crow::response& res, context& ctx)
    {
        
        std::string client_id = req.raw_url.substr(10);
        std::shared_ptr<models::Client> client = models::Client::get(client_id);
        
        if (!client) 
        {
            CROW_LOG_WARNING << "client not found";
            res.code = 404;
            res.end();
            return;
        }
        
        auto auth = req.headers.find("Authorization"); 
        if ((auth == req.headers.end()) && (auth->second.empty()))
        {   
            CROW_LOG_WARNING << "authorization header error";
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
            token = authorization.substr(authorization.find(' ') + 1);
        else
        {
            CROW_LOG_WARNING << "token bearer error";
            res.code = 401;
            res.end();
            return;
        }
        
        if (token == client->registration_access_token)
            ctx.req_client = *client;
        else
        {
            CROW_LOG_WARNING << "token validation error";
            res.code = 403;
            res.end();
            return;
        }
    }

    void after_handle(crow::request& req, crow::response& res, context& ctx){}
};

#endif

