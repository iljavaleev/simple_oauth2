#ifndef Handlers_hpp
#define Handlers_hpp
#include "crow.h"
#include "AuthMiddlware.hpp"


struct Resource{
    Resource(crow::App<AuthMW>& _app):app(_app){}
    crow::response operator()(const crow::request& req) const;
private:
    crow::App<AuthMW>& app;
};

struct Words{
    Words(crow::App<AuthMW>& _app):app(_app){}
    crow::response operator()(const crow::request& req) const;
private:
    crow::App<AuthMW>& app;
};


#endif