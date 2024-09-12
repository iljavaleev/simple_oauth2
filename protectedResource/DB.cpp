#include "DB.hpp"
#include <mongocxx/uri.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/stdx.hpp>
#include <mongocxx/client.hpp>
#include <unordered_set>

#include <bsoncxx/array/view.hpp>
#include <bsoncxx/builder/basic/array.hpp>
#include <bsoncxx/stdx/string_view.hpp>
#include <bsoncxx/string/to_string.hpp>

bool Auth::token_exists(const std::string& token)
{
    auto dbtoken = 
        collection.find_one(make_document(kvp("access_token", token)));
    if (!dbtoken)
        return false;
    return true;
}


std::unordered_set<std::string> Auth::get_scope(
    const std::string& token)
{
    std::unordered_set<std::string> res;
    auto output = 
        collection.find_one(make_document(kvp("access_token", token)));
    if (!output)
    {   
        return res;
    }
        
    bsoncxx::array::view subarr;
    try
    {
       subarr = output->view()["scope"].get_array().value;
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return res;
    }
    for (bsoncxx::array::element el: subarr)
        res.insert(bsoncxx::string::to_string(el.get_string().value));
    return res;
}
