#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <mongocxx/stdx.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <iostream>

std::string getServerKey(char *ip) {
    mongocxx::instance instance{};
    mongocxx::client client{mongocxx::uri{"mongodb://localhost:27017"}};

    auto db = client["servers_bd"];
    auto collection = db["offacc_servers"];

    bsoncxx::builder::stream::document filter_builder;
    filter_builder << "server_ip" << ip;

    auto cursor = collection.find(filter_builder.view());

    for (auto&& doc : cursor) {
        auto public_key = doc["public_key"].get_utf8().value;
        std::string str(public_key);
        return str;
    }
}

int main() {
    std::cout << getServerKey("localhost:1201") << std::endl;
    return 0;
}

