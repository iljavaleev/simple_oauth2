#include <crow.h>
#include "AuthMiddlware.hpp"
#include "Handlers.hpp"


int main()
{
    crow::App<AuthMW> app;
    
    CROW_ROUTE(app, "/resource")
    .CROW_MIDDLEWARES(app, AuthMW)
    .methods(crow::HTTPMethod::POST)(Resource(app));
    
    CROW_ROUTE(app, "/")
    .methods(crow::HTTPMethod::GET)(idx());

    app.port(9002).run();
    return 0;
}    