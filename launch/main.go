package main

import (
	"github.com/rightjoin/aqua"
	cubeUser "user/api/service"
)

// main function
func main() {
	server := aqua.NewRestServer()
	server.AddService(&cubeUser.User{})
	server.Run()
}
