#ifndef Handlers_hpp
#define Handlers_hpp

#include "crow.h"
#include "ClientMetadataMW.hpp"
#include "AuthorizeConfigurationMW.hpp"

struct idx
{
    crow::mustache::rendered_template operator()(
        const crow::request& req) const;
};

struct authorize
{
    crow::mustache::rendered_template operator()(
        const crow::request& req) const;
};

struct approve
{
    crow::response operator()(const crow::request& req) const;
};

struct token
{
    crow::response operator()(const crow::request& req) const;
};

struct public_key
{
   crow::response operator()(const crow::request& req) const;
};

struct revoke_handler
{
   crow::response operator()(const crow::request& req) const;
};

struct register_handler
{
    crow::App<ClientMetadataMW, AuthorizeConfigurationMW>& app;
    register_handler(
        crow::App<ClientMetadataMW, AuthorizeConfigurationMW>& _app):app(_app){}
    crow::response operator()(const crow::request& req) const;
};

struct client_management_handler
{
    crow::App<ClientMetadataMW, AuthorizeConfigurationMW>& app;
    client_management_handler(
        crow::App<ClientMetadataMW, AuthorizeConfigurationMW>& _app):app(_app){}
    crow::response operator()(const crow::request&, std::string&&) const;
};

#endif
