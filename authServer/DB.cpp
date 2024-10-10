#include "DB.hpp"

#include <unordered_set>
#include <memory>
#include <ctime>
#include <iomanip>

#include <bsoncxx/document/value.hpp>
#include <bsoncxx/array/view.hpp>
#include <bsoncxx/builder/basic/array.hpp>
#include <bsoncxx/stdx/string_view.hpp>
#include <bsoncxx/string/to_string.hpp>

using namespace std::literals;

using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::sub_array;

std::unique_ptr<DB> db = std::make_unique<DB>();

const std::unordered_set<std::string> 
Client::token_endpoint_auth_methods{"secret_basic", "secret_post", "none"};


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
        return std::shared_ptr<Client>();
    std::shared_ptr<Client> client_res = std::make_shared<Client>();
    
    bsoncxx::document::view client = client_value->view();
    
    bsoncxx::array::view subarr{client["redirect_uris"].get_array().value};
    for (bsoncxx::array::element ele : subarr)
        client_res->redirect_uris.push_back(
            bsoncxx::string::to_string(ele.get_string().value)
        );           
    
    subarr = client["scope"].get_array().value;
    for (bsoncxx::array::element ele : subarr)
        client_res->scopes.insert(
            bsoncxx::string::to_string(ele.get_string().value)
        );

    subarr = client["grant_types"].get_array().value;
    for (bsoncxx::array::element ele : subarr)
        client_res->grant_types.insert(
            bsoncxx::string::to_string(ele.get_string().value)
        );
    
    subarr = client["response_types"].get_array().value;
    for (bsoncxx::array::element ele : subarr)
        client_res->response_types.insert(
            bsoncxx::string::to_string(ele.get_string().value)
        );
    
    client_res->client_id = bsoncxx::string::to_string(
        client["client_id"].get_string().value);

    client_res->token_endpoint_auth_method = bsoncxx::string::to_string(
        client["token_endpoint_auth_method"].get_string().value);
    
    client_res->client_id_created_at = 
        client["client_id_created_at"].get_int64();
    client_res->client_id_expires_at = 
        client["client_id_expires_at"].get_int64();
    
    if(client["client_secret"])
        client_res->client_secret = bsoncxx::string::to_string(
            client["client_secret"].get_string().value);

    if (client["client_name"])
        client_res->client_name =  bsoncxx::string::to_string(
            client["client_name"].get_string().value);

    if (client["client_uri"])
        client_res->client_name =  bsoncxx::string::to_string(
            client["client_uri"].get_string().value);
    
    return client_res;
}


 std::vector<std::shared_ptr<Client>> Client::get_all()
 {
    std::vector<std::shared_ptr<Client>> res;
    auto clients_doc = db->get_client_collection().find({});
    for (auto client: clients_doc)
    {
        std::vector<std::string> uris;
        std::unordered_set<std::string> scopes;
        bsoncxx::array::view subarr{client["redirect_uris"].get_array().value};
        for (bsoncxx::array::element ele : subarr)
            uris.push_back(bsoncxx::string::to_string(ele.get_string().value));           
        
        subarr = client["scope"].get_array().value;
        for (bsoncxx::array::element ele : subarr)
            scopes.insert(bsoncxx::string::to_string(ele.get_string().value));

        res.push_back(std::make_shared<Client>(
            bsoncxx::string::to_string(client["client_id"].get_string().value),
            bsoncxx::string::to_string(
                client["client_secret"].get_string().value),
            uris,
            scopes
        ));
    }
    return res;
 }

bool Client::destroy(const std::string& client_id)
{   
    auto res = db->get_client_collection().delete_one(
        make_document(kvp("client_id", client_id)));
    return res->deleted_count() != 0;
}


void Request::create()
{
    try
    {
        db->get_request_collection().
            insert_one(
                make_document(kvp("req_id", req_id), kvp("query", query)));
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}


bool Request::destroy(const std::string& req_id)
{
    auto res = db->get_request_collection().delete_one(
        make_document(kvp("req_id", req_id)));
    return res->deleted_count() != 0;
}


std::shared_ptr<Request> Request::get(const std::string& req_id)
{
    auto request_value = db->get_request_collection().
        find_one(make_document(kvp("req_id", req_id)));
    if (!request_value)
        return nullptr;
    
    return std::make_shared<Request>(
        req_id,
        bsoncxx::string::to_string(
        request_value->view()["query"].get_string().value));
}


void Code::create()
{
    try
    {
        auto doc = bsoncxx::builder::basic::document{};
        doc.append(kvp("code", code));
        doc.append(kvp("query", query));
        doc.append(kvp("scope", [this](sub_array child) 
        {
            for (const auto& uri : scopes) 
            {
                child.append(uri);
            }
        }));
        db->get_code_collection().insert_one(doc.view());
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}


std::shared_ptr<Code> Code::get(const std::string& code)
{
    auto code_value = db->get_code_collection().
        find_one(make_document(kvp("code", code)));
    if (!code_value)
        return std::shared_ptr<Code>();
    
    std::unordered_set<std::string> scopes;
    bsoncxx::array::view subarr{code_value->view()["scope"].get_array().value};
    for (bsoncxx::array::element ele : subarr)
        scopes.insert(bsoncxx::string::to_string(ele.get_string().value)); 
    
    return std::make_shared<Code>(
        bsoncxx::string::to_string(
            code_value->view()["code"].get_string().value),
        bsoncxx::string::to_string(
            code_value->view()["query"].get_string().value),
        scopes
    );
}


bool Code::destroy(const std::string& code)
{
    auto res = db->get_code_collection().
        delete_one(make_document(kvp("code", code)));
    return res->deleted_count() != 0;
}


void Token::create()
{
    mongocxx::options::update options;
    options.upsert(true);
    
    auto doc = bsoncxx::builder::basic::document{};
    doc.append(kvp("client_id", client_id));
    doc.append(kvp("scope", [this](sub_array child) 
    {
        for (const auto& uri : scopes) 
        {
            child.append(uri);
        }
    }));
    
    std::shared_ptr<std::string> expire_string{nullptr};
    std::string token_type{"access_token"};
    if (!expire)
        token_type = "refresh_token";
    
    doc.append(kvp("expire", int64_t(expire)));

    doc.append(kvp(token_type, token));
    
    auto prev = bsoncxx::builder::basic::document{};
    prev.append(kvp("client_id", client_id));
    prev.append(kvp(token_type, make_document(kvp("$exists", true))));

    auto outer = bsoncxx::builder::basic::document{};
    outer.append(kvp("$set", doc));

    db->get_token_collection().update_one(
        prev.view(), outer.view(), options);
}

void Token::create(
    const std::string& token,
    const std::string& client_id, 
    std::time_t exp,
    std::unordered_set<std::string> scopes    
    )
{
    mongocxx::options::update options;
    options.upsert(true);
    
    auto doc = bsoncxx::builder::basic::document{};
    doc.append(kvp("client_id", client_id));
    doc.append(kvp("scope", [&scopes](sub_array child) 
    {
        for (const auto& uri : scopes) 
        {
            child.append(uri);
        }
    }));
    
    std::string token_type{"access_token"};
    if (!exp)
        token_type = "refresh_token";
    
    doc.append(kvp("expire", int64_t(exp)));

    std::string hash_token = std::to_string(std::hash<std::string>{}(token));

    doc.append(kvp(token_type, hash_token));
    
    auto prev = bsoncxx::builder::basic::document{};
    prev.append(kvp("client_id", client_id));
    prev.append(kvp(token_type, make_document(kvp("$exists", true))));

    auto outer = bsoncxx::builder::basic::document{};
    outer.append(kvp("$set", doc));

    db->get_token_collection().update_one(
        prev.view(), outer.view(), options);
}


std::shared_ptr<Token> Token::get(
    const std::string& token,
    const std::string& type
    )
{
    
    std::size_t hash_token = std::hash<std::string>{}(token);
    std::string token_type(std::move(type));

    auto doc = db->get_token_collection().
        find_one(make_document(kvp(token_type, std::to_string(hash_token))));
    if (!doc)
        return std::shared_ptr<Token>();
    std::unordered_set<std::string> scopes;
   
    bsoncxx::array::view subarr{doc->view()["scope"].get_array().value};
    for (bsoncxx::array::element ele : subarr)
        scopes.insert(bsoncxx::string::to_string(ele.get_string().value));
    
    
    return std::make_shared<Token>(
        bsoncxx::string::to_string(doc->view()[token_type].get_string().value),
        bsoncxx::string::to_string(doc->view()["client_id"].get_string().value),
        doc->view()["expire"].get_int64(),
        scopes
    );
}


bool Token::destroy_all(const std::string& client_id)
{   
    auto res = db->get_token_collection().delete_many(
        make_document(kvp("client_id", client_id)));
    return res->deleted_count() != 0;
}


bool Token::destroy(const std::string& client_id, const std::string& type)
{   
    std::string token_type{type};
    auto res = db->get_token_collection().delete_one(
        make_document(
            kvp("client_id", client_id), 
            kvp(token_type, make_document(kvp("$exists", true)))));
    return res->deleted_count() != 0;
}
