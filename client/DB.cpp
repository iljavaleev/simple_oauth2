#include "DB.hpp"

#include <unordered_set>
#include <memory>

#include "Utils.hpp"
#include <nlohmann/json.hpp>
#include <bsoncxx/document/value.hpp>
#include <bsoncxx/array/view.hpp>
#include <bsoncxx/builder/basic/array.hpp>
#include <bsoncxx/stdx/string_view.hpp>
#include <bsoncxx/string/to_string.hpp>


using namespace std::literals;
using json = nlohmann::json;
using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::sub_array;


std::unique_ptr<DB> db = std::make_unique<DB>();

const std::unordered_set<std::string> 
models::Client::token_endpoint_auth_methods{
    "secret_basic", "secret_post", "none"};

const std::string 
models::Client::client_uri = std::format(
    "http://{}:{}", 
    std::getenv("CLIENT"), 
    std::getenv("CLIENT_PORT")
);

namespace models
{
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

        doc.append(kvp("registration_client_uri", registration_client_uri));
        doc.append(kvp("registration_access_token", registration_access_token));

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
            for (const auto& s : scope) 
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
            client_res->scope.insert(
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

        client_res->access_token = bsoncxx::string::to_string(
            client["access_token"].get_string().value);

        client_res->refresh_token = bsoncxx::string::to_string(
            client["refresh_token"].get_string().value);

        client_res->token_endpoint_auth_method = bsoncxx::string::to_string(
            client["token_endpoint_auth_method"].get_string().value);
        
        client_res->registration_access_token = bsoncxx::string::to_string(
            client["registration_access_token"].get_string().value);
            
        client_res->registration_client_uri = bsoncxx::string::to_string(
            client["registration_client_uri"].get_string().value);
        
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

    void to_json(json& j, const Client& cl) 
    {
        j = json{ 
            {"access_token", cl.access_token},
            {"refresh_token", cl.refresh_token},
            {"client_id", cl.client_id}, 
            {"client_secret", cl.client_secret}, 
            {"scope", json(cl.scope)}, 
            {"redirect_uris", json(cl.redirect_uris)},
            {"client_id_created_at", cl.client_id_created_at},
            {"client_id_expires_at", cl.client_id_expires_at},
            {"grant_types", json(cl.grant_types)},
            {"response_types", json(cl.response_types)},
            {"client_name", cl.client_name},
            {"token_endpoint_auth_method", cl.token_endpoint_auth_method}, 
            {"registration_client_uri", cl.registration_client_uri},
            {"registration_access_token", cl.registration_access_token} 
        };
    }

    void from_json(const json& j, Client& cl) 
    {
        if (j.contains("access_token"))
            j.at("access_token").get_to(cl.access_token);
        if (j.contains("refresh_token"))
            j.at("refresh_token").get_to(cl.refresh_token);
        j.at("client_id").get_to(cl.client_id);
        j.at("client_secret").get_to(cl.client_secret);
        j.at("scope").get_to(cl.scope);
        j.at("redirect_uris").get_to(cl.redirect_uris);
        j.at("client_id_created_at").get_to(cl.client_id_created_at);
        j.at("client_id_expires_at").get_to(cl.client_id_expires_at);
        j.at("grant_types").get_to(cl.grant_types);
        j.at("response_types").get_to(cl.response_types);
        j.at("client_name").get_to(cl.client_name);
        j.at("token_endpoint_auth_method").get_to(cl.token_endpoint_auth_method);
        j.at("registration_client_uri").get_to(cl.registration_client_uri);
        j.at("registration_access_token").get_to(cl.registration_access_token);
    }
}