#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>

class EnvParser {
public:
    bool load(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Could not open the file: " << filename << std::endl;
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            trim(line);
            // ignore empty str & comments
            if (line.empty() || line[0] == '#') {
                continue;
            }

            // divide str on key & val
            size_t pos = line.find('=');
            if (pos == std::string::npos) {
                std::cerr << "Invalid line: " << line << std::endl;
                continue;
            }

            std::string key = trim(line.substr(0, pos));
            std::string value = trim(line.substr(pos + 1));

            envMap[key] = value;
        }

        file.close();
        return true;
    }

    std::string get(const std::string& key) const {
        auto it = envMap.find(key);
        if (it != envMap.end()) {
            return it->second;
        }
        return "";
    }

private:
    std::map<std::string, std::string> envMap;

    std::string trim(const std::string& str) { // rm space
        size_t first = str.find_first_not_of(' ');
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(' ');
        return str.substr(first, (last - first + 1));
    }
};

int main() {
    EnvParser parser;
    if (parser.load("config.env")) {
        std::string value = parser.get("TEST");
        if (!value.empty()) {
            std::cout << "MY_VARIABLE: " << value << std::endl;
        } else {
            std::cout << "MY_VARIABLE not found." << std::endl;
        }
    }
    return 0;
}

