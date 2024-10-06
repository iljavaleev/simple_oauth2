#include "crow.h"  
#include <string>          
#include <vector>  
        
#include "DB.hpp"         
#include "Handlers.hpp"    


Client client(
    "oauth-client-1", 
    "oauth-client-secret-1", 
    {"http://localhost:9000/callback"},
    "foo bar"
);

ProtectedResource resource(
    "resource_id",
    "http://localhost:9002"
);


int main()
{
    client.create();
    
    crow::SimpleApp app;
    app.loglevel(crow::LogLevel::Warning);
    CROW_ROUTE(app, "/")
    .methods(crow::HTTPMethod::GET)(idx());

    CROW_ROUTE(app, "/authorize")
    .methods(crow::HTTPMethod::GET)(authorize());

    CROW_ROUTE(app, "/approve")
    .methods(crow::HTTPMethod::POST)(approve());

    CROW_ROUTE(app, "/token")
    .methods(crow::HTTPMethod::POST)(token());

    CROW_ROUTE(app, "/public_key")
    .methods(crow::HTTPMethod::POST)(public_key());

    CROW_ROUTE(app, "/revoke").methods(
        crow::HTTPMethod::POST)(revoke_handler());
    app.port(9001).run();
    return 0;
}
