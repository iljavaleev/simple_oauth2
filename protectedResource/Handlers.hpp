#ifndef Handlers_hpp
#define Handlers_hpp

#include "crow.h"
#include "AuthMiddlware.hpp"


struct idx{
    crow::mustache::rendered_template operator()(
        const crow::request& req) const;
};


struct Resource{
    Resource(crow::App<AuthMW>& _app):app(_app){}
    crow::response operator()(const crow::request& req) const;
private:
    crow::App<AuthMW>& app;
};


#endif
