#include <iostream>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <bsoncxx/json.hpp>

int main() {
    // Инициализация экземпляра MongoDB
    mongocxx::instance instance{};

    // Создание клиента
    mongocxx::client client{mongocxx::uri{}};

    // Подключение к базе данных и коллекции
    auto db = client["servers_bd"];
    auto collection = db["offacc_servers"];

    // Получение всех документов из коллекции
    auto cursor = collection.find({});

    // Вывод документов
    for (auto&& doc : cursor) {
        std::cout << bsoncxx::to_json(doc) << std::endl;
    }

    return 0;
}

