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

- `std::vector<DbIp> swParseIpList(const std::string &filename)` - Get IP list of **OffAccS**.

- `void freeDbIpVector(std::vector<DbIp>& db_ips)` - Just for free IP list after exit.

- `UserConf swParseConfig()` - To parse User Config by reading `config.env`.

- `std::string swGenSalt()` - To generate *"salt"* for **SW** protocol.

- `std::string swCypherMsg(std::string package, void* pub_key, std::string salt)` - To encrypt the message.

- `void swLoadKeys(UserConf *u_cfg, std::string pu_key, std::string pr_key)` - For load **public & private** RSA keys.

- `int swGenKeys(char *pu_key, char *pr_key)` - To generate **public & private** RSA keys.

### Cypher System

For example we take message **"Hello World"**:

`SW349ZCDXSNsdA3AdsasadZXCQ233SAfDC:3267AVSDrews23465dstA5d5sarA`.

> [!WARNING]
> It's just *example*! In **SecretWay**
> salt is **120 bytes**. Also **encrypted message**
> has **2048 bytes**.

- SW means signature that message didn't corrupted.
- After **SW** is cyphered message.
- **":"** is salt for aprove that message isn't corrupted too.

Here is **decrypted message:**

```json
{
    "userId": "0",
    "password": "1234",
    "sendUserId": "0",
    "msg": "Hello world",

    "salt": "3267AVSDrews23465dstA5d5sarA"
}
```
