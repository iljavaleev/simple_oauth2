#include <crow.h>
#include "AuthMiddlware.hpp"
#include "Handlers.hpp"


int main()
{
    crow::App<AuthMW> app;
    
    CROW_ROUTE(app, "/resource")
    .CROW_MIDDLEWARES(app, AuthMW)
    .methods(crow::HTTPMethod::GET, crow::HTTPMethod::POST)(Resource(app));
    
    CROW_ROUTE(app, "/words")
    .CROW_MIDDLEWARES(app, AuthMW)
    .methods(
        crow::HTTPMethod::GET, 
        crow::HTTPMethod::POST, 
        crow::HTTPMethod::DELETE)(Words(app));

    app.port(9002).run();
    return 0;
}    