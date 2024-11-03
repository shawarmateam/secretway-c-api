# SecretWay C++ API

Offical **API** client in `C++` for [SecretWay](https://github.com/shawarmateam/secretway).

## Documentation

**SecretWay** API has the struct of *client config*:
```cpp
struct UserConf
{
    char* id;                 // User ID
    char* password;           // User password
    const char* private_key;  // Private Key to decrypt msgs using RSA
    const char* public_key;   // Public Key to send msgs to you
    const bool client = true; // To display that you are a client
};
```

To send message you need to use **swSendMsg()**.

### Functions

- `swSendMsg(const char* msg, const char* s_ui, UserConf *u_cfg)` - Send message to user.

