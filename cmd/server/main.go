package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/ruidanwang/vulscanner/vulscanner/pkg/router"
)

func main() {
	r := gin.Default()

	router.Register(r)

	log.Println("server started at :8090")
	if err := r.Run(":8090"); err != nil {
		log.Fatal(err)
	}
}
