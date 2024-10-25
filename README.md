# SecretWay C++ API

Offical **API** client in `C++` for [SecretWay](https://github.com/shawarmateam/secretway).

## Documentation

**SecretWay** API has the struct of *client config*:
```cpp
struct UserConf
{
    char** db_ips; // IPs of databases

    char* id; // User ID
    char* password; // User password
    const char* private_key;
    const char* public_key;
    const bool client = true;
};
```

### Functions

- `swSendMsg(const char* msg, const char* s_ui, UserConf *u_cfg)` - Send message to user.

