#include <crow.h>
#include <nlohmann/json.hpp>
#include "Handlers.hpp"
#include "DB.hpp"

int main()
{
    Client client(
        "oauth-client-1", 
        "oauth-client-secret-1", 
        {"http://localhost:9000/callback"},
        "foo bar"
    );
    client.create();
    
    crow::SimpleApp app;
    crow::mustache::set_global_base("../files");
    CROW_ROUTE(app, "/authorize")
    .methods(crow::HTTPMethod::GET)(authorize());

    CROW_ROUTE(app, "/approve")
    .methods(crow::HTTPMethod::POST)(approve());

    CROW_ROUTE(app, "/token")
    .methods(crow::HTTPMethod::POST)(token());

    app.port(9001).run();
    return 0;
}