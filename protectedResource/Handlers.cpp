#include "Handlers.hpp"

#include <string>
#include <unordered_set>

#include "AuthMiddlware.hpp"
#include <nlohmann/json.hpp>

using json = nlohmann::json;


json foo_resource = {
	{"name", "FOO Protected Resource"},
	{"description", "This data has been protected by OAuth 2.0"}
};

json bar_resource = {
	{"name", "BAR Protected Resource"},
	{"description", "This data has been protected by OAuth 2.0"}
};


crow::mustache::rendered_template idx::operator()(const crow::request& req) const
{
    crow::mustache::set_base("../files");
    auto page = crow::mustache::load_text("index.html");
    return page;
}


crow::response Resource::operator()(const crow::request& req) const
{
    const auto& ctx = app.get_context<AuthMW>(req);
    std::string token = ctx.token;
    std::unordered_set<std::string> scope = ctx.scope;
    printf("1\n");
    json resp_json;
    for (const auto& s: scope)
    {
        if(s == "foo")
            resp_json.push_back(foo_resource);
        if(s == "bar")
            resp_json.push_back(bar_resource);
    }
    crow::response res;
    res.body = resp_json.dump();
    return res;
}
