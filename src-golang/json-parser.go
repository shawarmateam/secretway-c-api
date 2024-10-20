package main

import (
	"encoding/json"
	"fmt"
	"log"
	"flag"
)

// Alloc struct
type Package struct {
	Msg        string `json:"msg"`
	UserId     string `json:"userId"`
	Password   string `json:"password"`
    SendUserId int    `json:"sendUserId"`
    IsClient   bool   `json:"client"`
}

func main() {
    msg := flag.String("msg",      "",   "Set message")
    id  := flag.String("id",       "",   "Your SecretWay user ID")
    pw  := flag.String("pw",       "",   "Your user ID")
    sui :=    flag.Int("sui",    -666,   "User ID to send")

    flag.Parse()

    // Checking
    if *msg == "" || *id == "" || *pw == "" || *sui == -666 {
        log.Fatal("E: too few arguments. Args: ", *msg, *id, *pw, *sui)
	}

	// Struct
	usr_package := Package {
		Msg:        *msg,
        UserId:     *id,
        Password:   *pw,
        SendUserId: *sui,
        IsClient:   true,
	}

	// Converting into JSON
	jsonData, err := json.Marshal(usr_package)
	if err != nil {
        log.Fatalf("E: failed convert to JSON: %s", err)
	}

	// Output
	fmt.Println(string(jsonData))
}

