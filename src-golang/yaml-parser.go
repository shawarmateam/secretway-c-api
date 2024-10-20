package main

import (
    "fmt"
    "io/ioutil"
    "log"
    "gopkg.in/yaml.v2"
)

type Config struct {
    DbIps[] string `yaml:"secretway-db-ips"`
}

func main() {
    // Reading YAML config
    data, err := ioutil.ReadFile("config.yaml")
    if err != nil {
        log.Fatalf("error: %v", err)
    }

    // Create a struct
    var config Config

    // if err
    err = yaml.Unmarshal(data, &config)
    if err != nil {
        log.Fatalf("error: %v", err)
    }

    // Output
	for _, ip := range config.DbIps {
		fmt.Println(ip)
	}
    fmt.Println("\n")
}

