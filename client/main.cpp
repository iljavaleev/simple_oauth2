#include "crow.h"
#include <nlohmann/json.hpp>
#include "DB.hpp"
#include "Handlers.hpp"
 

Server s("http://localhost:9001/authorize", "http://localhost:9001/token");


int main()
{
    crow::SimpleApp app;
    Client cl;
    std::shared_ptr<Client> cl_ptr = Client::get();
    if (cl_ptr)
        cl = *cl_ptr;
    CROW_ROUTE(app, "/").methods(
        crow::HTTPMethod::GET)(idx(cl));
    CROW_ROUTE(app, "/authorize").methods(
        crow::HTTPMethod::GET)(authorize(cl, s));
    CROW_ROUTE(app, "/callback").methods(
        crow::HTTPMethod::POST)(callback(cl, s));
    CROW_ROUTE(app, "/fetch_resource").methods(
        crow::HTTPMethod::GET)(fetch_resource(cl, s));
    CROW_ROUTE(app, "/revoke_access").methods(
        crow::HTTPMethod::POST)(revoke_handler(cl));
    CROW_ROUTE(app, "/revoke_refresh").methods(
        crow::HTTPMethod::POST)(revoke_refresh_handler(cl));
    
    CROW_ROUTE(app, "/read_client").methods(
        crow::HTTPMethod::GET)(read_client(cl));
    CROW_ROUTE(app, "/update_client").methods(
        crow::HTTPMethod::POST)(update_client(cl));
    CROW_ROUTE(app, "/unregister_client").methods(
        crow::HTTPMethod::GET)(delete_client(cl));
    app.port(9000).run();
    return 0;
}
