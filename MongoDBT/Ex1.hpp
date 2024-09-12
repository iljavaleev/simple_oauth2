#ifndef Ex1_hpp
#define Ex1_hpp

#include <cstdint>
#include <iostream>
#include <vector>
#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/json.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/stdx.hpp>
#include <mongocxx/uri.hpp>
using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_array;
using bsoncxx::builder::basic::make_document;


void insrt_doc()
{
    // mongocxx::instance instance{}; // This should be done only once.
    mongocxx::uri uri("mongodb://localhost:27017");
    mongocxx::client client(uri);
    
    auto db = client["shop"];
    auto collection = db["js"];

    auto document = make_document(kvp("some", 12), kvp("arr", make_array("a", "b", "c")));
    collection.insert_one(document.view());
}

 bsoncxx::document::value create_document()
 {
    mongocxx::uri uri("mongodb://localhost:27017");
    mongocxx::client client(uri);
    
    auto db = client["shop"];
    auto collection = db["js"];

    return make_document(
        kvp("some", 12), 
        kvp("arr", make_array("a", "b", "c")),
        kvp("d", make_document(kvp("nest", 21))));
    
 }
 


#endif