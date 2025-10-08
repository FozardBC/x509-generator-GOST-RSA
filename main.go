package main

import (
	"html-cer-gen/internal/api"
	"html-cer-gen/internal/config"
	"html-cer-gen/internal/logger"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	gin.SetMode(gin.ReleaseMode)

	cfg := config.MustRead()

	log := logger.New(logger.LevelDebug)

	log.Info("Starting App", "LOGLEVEL", cfg.LogLevel)

	API := api.New(log)
	API.Setup()

	srv := http.Server{
		Addr:    "192.168.20.106:" + cfg.ServerPort,
		Handler: API.Router,
	}

	err := srv.ListenAndServe()
	if err != nil {
		log.Error(err.Error())
	}
}
