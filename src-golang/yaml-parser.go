package main

import (
    "fmt"
    "io/ioutil"
    "log"
    "gopkg.in/yaml.v2"
    "os"
)

type Config struct {
	DbIps          []string `yaml:"secretway-db-ips"`
	User           User     `yaml:"user"`
}

type User struct {
	Id         string `yaml:"id"`
	Password   string `yaml:"password"`
	PrivateKey string `yaml:"private_key"`
	PublicKey  string `yaml:"public_key"`
}

func cr_config() {
// Coming soon...
}

func ch_rules() {
	fileInfo, err := os.Stat("config.yaml")
	if err != nil {
		log.Fatalf("E: failed to get info of config.yaml", err)
	}

	if (fileInfo.Mode().String() != "-rw-------") {
        err = os.Chmod("config.yaml", 0600)

        if err != nil {
		    log.Fatalf("E: failed to change rules of config.yaml to 0600", err)
	    }
    }
}

func main() {
    ch_rules();

    // Reading YAML config
    data, err := ioutil.ReadFile("config.yaml")
    if err != nil {
        log.Fatalf("E: %v", err)
    }

    // Create a struct
    var config Config

    // if err
    err = yaml.Unmarshal(data, &config)
    if err != nil {
        log.Fatalf("E: %v", err)
    }

    // Output
	for _, ip := range config.DbIps {
		fmt.Println(ip)
	}

    fmt.Println(config.User.Id)
    fmt.Println(config.User.Password)
    fmt.Println(config.User.PrivateKey)
    fmt.Println(config.User.PublicKey)
}

