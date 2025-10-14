package main

import (
	"html-cer-gen/internal/api"
	"html-cer-gen/internal/config"
	"html-cer-gen/internal/logger"
	"net/http"
	"os"
	"path/filepath"
	"time"

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

	go func() {
		log.Info("Служба очистки кеша запущена")
		for {

			time.Sleep(72 * time.Hour)

			err := ClearDir("./certs/generated/")
			if err != nil {
				log.Warn("Не получилось очистить директорию", "Ошибка", err.Error())
			}

			log.Info("Папка generated очищена")

		}

	}()

	err := srv.ListenAndServe()
	if err != nil {
		log.Error(err.Error())

	}

}

func ClearDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()

	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}

	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}

	return nil
}
