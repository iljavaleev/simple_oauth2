#include "DB.hpp"

#include <unordered_set>
#include <memory>

#include "Utils.hpp"
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


const std::string Client::client_uri = std::format(
    "{}:{}", 
    std::getenv("CLIENT"), 
    std::getenv("CLIENT_PORT")
);


void Client::save()
{   
    mongocxx::options::update options;
    options.upsert(true);

    auto cl = bsoncxx::builder::basic::document{};
    cl.append(kvp("client_uri", Client::client_uri));
    
    auto doc = bsoncxx::builder::basic::document{};
    doc.append(kvp("client_uri", Client::client_uri));
    doc.append(kvp("client_id", client_id));
    doc.append(kvp("client_secret", client_secret));
    
    doc.append(kvp("client_id_created_at", int64_t(client_id_created_at)));
    doc.append(kvp("client_id_expires_at", int64_t(client_id_expires_at)));
    doc.append(kvp("token_endpoint_auth_method", token_endpoint_auth_method));
    doc.append(kvp("access_token", access_token));
    doc.append(kvp("refresh_token", refresh_token));
    
    if (!client_name.empty())   
        doc.append(kvp("client_name", client_name));

    doc.append(kvp("redirect_uris", [this](sub_array child) 
    {
        for (const auto& uri : redirect_uris) 
        {
            child.append(uri);
        }
    }));
        
    doc.append(kvp("grant_types", [this](sub_array child) 
    {
        for (const auto& s : grant_types) 
        {
            child.append(s);
        }
    }));

    doc.append(kvp("response_types", [this](sub_array child) 
    {
        for (const auto& s : response_types) 
        {
            child.append(s);
        }
    }));

    doc.append(kvp("scope", [this](sub_array child) 
    {
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


std::shared_ptr<Client> Client::get()
{
    auto client_value = db->get_client_collection().
        find_one(make_document(kvp("client_uri", Client::client_uri)));
    
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

    return client_res;
}


bool Client::destroy(const std::string& client_id)
{   
    auto res = db->get_client_collection().delete_one(
        make_document(kvp("client_id", client_id)));
    return res->deleted_count() != 0;
}


std::shared_ptr<State> State::get(const Client& client)
{
    auto state_value = db->get_state_collection().
        find_one(make_document(kvp("client_id", client.client_id)));
    
    if (!state_value)
        return std::shared_ptr<State>();
    std::shared_ptr<State> res = std::make_shared<State>();
    
    bsoncxx::document::view state = state_value->view();

    res->client_id = bsoncxx::string::to_string(
        state["client_id"].get_string().value);
    res->state = bsoncxx::string::to_string(
        state["state"].get_string().value);
    return res;
}

std::shared_ptr<State> State::create(const Client& client)
{
    std::shared_ptr<State> res = std::make_shared<State>();
    srand((unsigned)time(NULL) * getpid());
    std::string state = gen_random(12);
    res->state = state;
    res->client_id = client.client_id;

    mongocxx::options::update options;
    options.upsert(true);

    auto st = bsoncxx::builder::basic::document{};
    st.append(kvp("client_id", client.client_id));
    
    auto doc = bsoncxx::builder::basic::document{};
    doc.append(kvp("client_id", client.client_id));
    doc.append(kvp("state", state));

    auto outer = bsoncxx::builder::basic::document{};
    outer.append(kvp("$set", doc));
    try
    {
        db->get_state_collection().update_one(
            st.view(), outer.view(), options);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    return res;
}
    