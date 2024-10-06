#include "crow.h"
#include "AuthMiddlware.hpp"
#include "Handlers.hpp"

ProtectedResource resource(
    "resource_id",
    "http://localhost:9002"
);

int main()
{
    crow::App<AuthMW> app;
    app.loglevel(crow::LogLevel::Warning);

    CROW_ROUTE(app, "/resource")
    .CROW_MIDDLEWARES(app, AuthMW)
    .methods(crow::HTTPMethod::POST)(Resource(app));
    
    CROW_ROUTE(app, "/")
    .methods(crow::HTTPMethod::GET)(idx());

    app.port(9002).run();
    return 0;
}
