#include "DB.hpp"

#include <unordered_set>
#include <memory>

#include <bsoncxx/document/value.hpp>
#include <bsoncxx/array/view.hpp>
#include <bsoncxx/builder/basic/array.hpp>
#include <bsoncxx/stdx/string_view.hpp>
#include <bsoncxx/string/to_string.hpp>



using namespace std::literals;

using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::sub_array;

std::unique_ptr<DB> db = std::make_unique<DB>();

void Client::create()
{   
    mongocxx::options::update options;
    options.upsert(true);

    auto cl = bsoncxx::builder::basic::document{};
    cl.append(kvp("client_id", client_id));
    
    auto doc = bsoncxx::builder::basic::document{};
    doc.append(kvp("client_id", client_id));
    doc.append(kvp("client_secret", client_secret));
    doc.append(kvp("redirect_uris", [this](sub_array child) {
        for (const auto& uri : redirect_uris) 
        {
            child.append(uri);
        }}));
        
    doc.append(kvp("scope", [this](sub_array child) {
        for (const auto& s : scopes) 
        {
            child.append(s);
        }
    }));

    auto outer = bsoncxx::builder::basic::document{};
    outer.append(kvp("$set", doc));
    try
    {
        db->get_client_collection().update_one(
            cl.view(), outer.view(), options);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}

std::shared_ptr<Client> Client::get(const std::string& client_id)
{
    auto client_value = db->get_client_collection().
        find_one(make_document(kvp("client_id", client_id)));
    if (!client_value)
        return nullptr;

    bsoncxx::document::view client = client_value->view();
    std::vector<std::string> uris;
    std::unordered_set<std::string> scopes;
    bsoncxx::array::view subarr{client["redirect_uris"].get_array().value};
    for (bsoncxx::array::element ele : subarr)
        uris.push_back(bsoncxx::string::to_string(ele.get_string().value));           
    
    subarr = client["scope"].get_array().value;
    for (bsoncxx::array::element ele : subarr)
        scopes.insert(bsoncxx::string::to_string(ele.get_string().value));

    return std::make_shared<Client>(
        bsoncxx::string::to_string(client["client_id"].get_string().value),
        bsoncxx::string::to_string(
            client["client_secret"].get_string().value),
        uris,
        scopes
    );
}

bool Client::destroy(const std::string& client_id)
{   
    auto res = db->get_client_collection().delete_one(
        make_document(kvp("client_id", client_id)));
    return res->deleted_count() != 0;
}


std::shared_ptr<Token> Token::get(const std::string& token, TokenType type)
{
    
    std::string token_type{"access_token"};
    if (type == TokenType::refresh)
        token_type = "refresh_token";
    
    auto doc = db->get_token_collection().
        find_one(make_document(kvp(token_type, token)));
    if (!doc)
        return std::shared_ptr<Token>();
    std::unordered_set<std::string> scopes;
   
    bsoncxx::array::view subarr{doc->view()["scope"].get_array().value};
    for (bsoncxx::array::element ele : subarr)
        scopes.insert(bsoncxx::string::to_string(ele.get_string().value));
    
    return std::make_shared<Token>(
        bsoncxx::string::to_string(doc->view()[token_type].get_string().value),
        bsoncxx::string::to_string(doc->view()["client_id"].get_string().value),
        type == TokenType::access ? 
            bsoncxx::string::to_string(
                doc->view()["expire"].get_string().value) : "",
        scopes,
        static_cast<TokenType>(doc->view()[token_type].get_int32().value)
    );
}

bool Token::destroy_all(const std::string& client_id)
{   
    auto res = db->get_token_collection().delete_many(
        make_document(kvp("client_id", client_id)));
    return res->deleted_count() != 0;
}

bool Token::destroy(const std::string& client_id, TokenType type)
{   
    std::string token_type{"access_token"};
    if (type == TokenType::refresh)
        token_type = "refresh_token";
    auto res = db->get_token_collection().delete_one(
        make_document(
            kvp("client_id", client_id), 
            kvp(token_type, true)));
    return res->deleted_count() != 0;
}

