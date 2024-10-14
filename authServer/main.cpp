#include "crow.h"  
#include <string>          
#include <vector>  
        
#include "DB.hpp"         
#include "Handlers.hpp"    


int main()
{ 
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

    CROW_ROUTE(app, "/register").methods(
        crow::HTTPMethod::POST)(register_handler());
    
    app.port(9001).run();
    return 0;
}
