package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/ruidanwang/vulscanner/pkg/router"

	docs "github.com/ruidanwang/vulscanner/docs"
    swaggerfiles "github.com/swaggo/files"
    ginSwagger "github.com/swaggo/gin-swagger"
)

func main() {
	r := gin.Default()
	docs.SwaggerInfo.BasePath = "/api"
	router.Register(r)
 	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	log.Println("server started at :8090")
	if err := r.Run(":8090"); err != nil {
		log.Fatal(err)
	}
}
