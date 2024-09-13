#include <crow.h>
#include <nlohmann/json.hpp>
#include "DB.hpp"
#include "Handlers.hpp"
 
Client cl(
    "oauth-client-1", 
    "oauth-client-secret-1",
    {"http://localhost:9000/callback", "http://localhost:9000/fetch_resource"}, 
    "foo"
);
    
Server s("http://localhost:9001/authorize", "http://localhost:9001/token");

int main()
{
    crow::SimpleApp app;
    CROW_ROUTE(app, "/").methods(
        crow::HTTPMethod::GET)(idx(cl));
    CROW_ROUTE(app, "/authorize").methods(
        crow::HTTPMethod::GET)(authorize(cl, s));
    CROW_ROUTE(app, "/callback").methods(
        crow::HTTPMethod::POST)(callback(cl, s));
     CROW_ROUTE(app, "/fetch_resource").methods(
        crow::HTTPMethod::GET)(fetch_resource(cl, s));
    app.port(9000).run();
    return 0;
}
