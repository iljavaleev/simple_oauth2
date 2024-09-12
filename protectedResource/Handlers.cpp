#include "Handlers.hpp"
#include "AuthMiddlware.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <sstream>
#include <chrono>
#include <vector>

using json = nlohmann::json;

json resource = {
	{"name", "Protected Resource"},
	{"description", "This data has been protected by OAuth 2.0"}
};

std::vector<std::string> saved_words;

crow::response Resource::operator()(const crow::request& req) const
{
    
    // std::cout << req.raw_url << std::endl;
    const auto& ctx = app.get_context<AuthMW>(req);
    std::string token = ctx.token;
    crow::response res;
    res.body = resource.dump();
    return res;
}


std::unordered_map<std::string, std::string> parse_form_data(std::string form)
{
    std::unordered_map<std::string, std::string> res;
    
    char pair_del = '&';
    char map_del = '=';
    std::vector<std::string> pairs;
    
    std::size_t start{}, stop{}; 
    std::string pair;
    while ((stop = form.find(pair_del)) != std::string::npos)
    {   
        pairs.emplace_back(form.substr(start, stop));
        start = stop + 1;
        form = form.substr(start);
    }
    pairs.emplace_back(form);
    std::string key, value;
    for (auto p: pairs)
    {
        stop = p.find(map_del);
        res.insert({p.substr(0, stop), p.substr(stop + 1)});    
    }
    return res;
}


crow::response Words::operator()(const crow::request& req) const
{
    const auto& ctx = app.get_context<AuthMW>(req);
    std::string token = ctx.token;
    crow::response res;
    res.code = 404;
    json j;
    for (auto str: saved_words)
        std::cout << str << std::endl;
    if (req.method == crow::HTTPMethod::GET)
    {
        if(!ctx.scope.contains("read"))
        {
            res.code = 403;
        }
        else
        {   
            std::ostringstream ss;
            for (auto w: saved_words)
            {
                ss << w << " ";
            }
            j["words"] = ss.str();
            ss.flush();
            const std::chrono::time_point now{std::chrono::system_clock::now()};
            const std::chrono::year_month_day ymd{std::chrono::floor<std::chrono::days>(now)};
 
            ss << "Current Year: " << static_cast<int>(ymd.year()) << ", "
                 "Month: " << static_cast<unsigned>(ymd.month()) << ", "
                 "Day: " << static_cast<unsigned>(ymd.day()) << "\n"
                 "ymd: " << ymd << '\n';
            
            j["timestamp"] = ss.str();

            res.body = j.dump();
            res.code = 200;
        }
    }
    else if (req.method == crow::HTTPMethod::POST)
    {
        if(!ctx.scope.contains("write"))
        {
            res.code = 403;
        }
        else
        {
            auto t = req.headers.find("Content-Type");

            std::string ctype = t->second;
            res.code = 201;
            if (ctype == "application/x-www-form-urlencoded")
            {
                auto form_map = parse_form_data(req.body);
                if(form_map.contains("word"))
                    saved_words.push_back(form_map.at("word"));
                else
                    res.code = 403;
            }  
            else
            {
                j = json::parse(req.body);
                if (j.contains("wors"))
                    saved_words.push_back(j["word"].dump());
                else
                    res.code = 403;
            }
        }
    }
    else if (req.method == crow::HTTPMethod::DELETE)
    {
        if(!ctx.scope.contains("delete"))
        {
            res.code = 403;
        }
        else
        {
            if(saved_words.empty())
            {
                res.code = 400;
            }
            else
            {
                saved_words.pop_back();
                res.code = 204;
            }
            
        }
    }
    else
        res.code = 404;
    return res;
}
