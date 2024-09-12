#include  "Ex1.hpp"

#include <crow.h>
#include <nlohmann/json.hpp>
#include <mongocxx/client.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/document/value.hpp>
#include "bsoncxx/oid.hpp"
#include <mongocxx/uri.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/stdx.hpp>
#include <vector>

#include <bsoncxx/types.hpp>
#include <bsoncxx/string/to_string.hpp>
#include <bsoncxx/builder/list.hpp>
#include <bsoncxx/builder/basic/array.hpp>
#include <bsoncxx/builder/basic/document.hpp>
#include <optional>
#include <bsoncxx/stdx/string_view.hpp>
using bsoncxx::builder::basic::kvp;
using bsoncxx::builder::basic::make_array;
using bsoncxx::builder::basic::make_document;
using bsoncxx::builder::basic::sub_array;


#include <bsoncxx/array/view.hpp>
#include <bsoncxx/builder/basic/array.hpp>
#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/builder/basic/kvp.hpp>
#include <bsoncxx/document/value.hpp>
#include <bsoncxx/document/view.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/stdx/string_view.hpp>
#include <bsoncxx/string/to_string.hpp>
#include <bsoncxx/types.hpp>
#include <bsoncxx/types/bson_value/view.hpp>

using namespace bsoncxx;

int main()
{   
    mongocxx::instance instance{};
    // insrt_doc();
    // auto doc = create_document();
    // auto v = doc.view();
    // auto el = v["some"];
    // std::cout << el.get_int32().value << std::endl;
    
    bsoncxx::builder::list list_builder = {"hello", {"nes", "shit"}};
    bsoncxx::document::view doc = list_builder.view().get_document();
    
    std::cout << doc["hello"].get_document().view()["nes"].get_string().value;

    const auto elements = {1, 2, 3};
    auto arr_build = bsoncxx::builder::basic::array{};
    for (const auto& a: elements)
        arr_build.append(a);

     auto doc_build = bsoncxx::builder::basic::document{};
     doc_build.append(kvp("key for arr", [&elements](sub_array arr){
        for (const auto& a: elements)
            arr.append(a);
     }));

    // auto x = v.get_array().value;  
    // mongocxx::instance instance{}; // This should be done only once.
    mongocxx::uri uri("mongodb://localhost:27017");
    mongocxx::client client(uri);
    
    auto db = client["shop"];
    auto collection = db["js"];
    // collection.insert_one(doc_build.view());
    auto output = collection.find_one(make_document(kvp("_id", bsoncxx::oid{bsoncxx::stdx::string_view{"66cedc0c622bd3cf7500f731"}})));
    if (output)
    {   
        bsoncxx::array::view subarr{output->view()["arr"].get_array().value};
        std:: cout << (subarr.find(4) != subarr.end()) << std::endl; // indx
        std::cout  << subarr[0].get_string().value << std::endl; 
        for (bsoncxx::array::element ele : subarr) 
        {
                std::cout << "array element: "
                              << bsoncxx::string::to_string(ele.get_string().value) << std::endl;
        }
        // std::cout << bsoncxx::string::to_string(output->view()["array"][0].get_string().value) << std::endl;
    }
   
    //std::cout << bsoncxx::string::to_string(output->view()["array"].get_string().value) << std::endl;
    // auto arr = output->view()["array"].get_array().value;
    // bsoncxx::builder::basic::array some_array{output->view()["array"].get_array().value};
    // for (auto a : arr)
    // {
    //     std::cout << a.get_utf8().value << std:: endl; 
    // }

    // auto insert_one_result = collection.insert_one(
    //     make_document(
    //         kvp("name", "insert name"),
    //         kvp("some_field", 99)));
    // assert(insert_one_result);
    
    // std::vector<bsoncxx::document::value> documents;
    // documents.push_back(make_document(kvp("i", 1)));
    // documents.push_back(make_document(kvp("i", 2)));
    // auto insert_many_result = collection.insert_many(
    //     documents);
    
    
    return 0;
}