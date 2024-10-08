#include "DB.hpp"


#include <unordered_set>

#include <bsoncxx/array/view.hpp>
#include <bsoncxx/builder/basic/array.hpp>
#include <bsoncxx/stdx/string_view.hpp>
#include <bsoncxx/string/to_string.hpp>


std::unique_ptr<DB> database = std::make_unique<DB>();


std::shared_ptr<Token> DB::get(const std::string& token)
{
    auto token_hash = std::hash<std::string>{}(token);
    auto doc = database->get_collection().
        find_one(make_document(kvp("access_token", std::to_string(token_hash))));
    if (!doc)
        return std::shared_ptr<Token>();
    
    std::unordered_set<std::string> scopes;

    bsoncxx::array::view subarr{doc->view()["scope"].get_array().value};
    for (bsoncxx::array::element ele : subarr)
        scopes.insert(bsoncxx::string::to_string(ele.get_string().value));
    return std::make_shared<Token>(
        bsoncxx::string::to_string(
            doc->view()["access_token"].get_string().value),
        bsoncxx::string::to_string(
            doc->view()["client_id"].get_string().value),
        doc->view()["expire"].get_int64(),
        scopes
    );
}
