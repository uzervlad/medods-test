package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"medods/database"
	_ "medods/docs"
	"medods/handlers"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title						MEDODS
// @version					1.0
// @securityDefinitions.apikey	ApiKeyAuth
// @in							header
// @name						Authorization
// @externalDocs.description	OpenAPI
// @externalDocs.url			https://swagger.io/resources/open-api/
func main() {
	config := fmt.Sprintf(
		"user=%v password=%v host=postgres port=5432 dbname=%v sslmode=disable",
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_DB"),
	)
	pool, err := pgxpool.New(context.Background(), config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	db := database.NewDatabase(pool)

	if !db.Initialize() {
		fmt.Println("Unable to initialize database")
		os.Exit(1)
	}

	router := gin.Default()
	router.GET("/", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"hello": "world",
		})
	})

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	handlers := handlers.CreateHandlers(pool, &db)

	router.GET("/tokens", handlers.GetTokens)
	router.POST("/refresh", handlers.RefreshToken)
	router.POST("/uuid", handlers.GetUUID)
	router.POST("/logout", handlers.Logout)

	router.Run(":8877")
}
