#ifndef Handlers_hpp
#define Handlers_hpp

#include "crow.h"


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

struct register
{
   crow::response operator()(const crow::request& req) const;
};

#endif
