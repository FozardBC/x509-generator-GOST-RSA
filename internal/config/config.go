package config

import (
	"log"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type Config struct {
	LogLevel   string `env:"LOG_LEVEL" env-default:"debug"`
	ServerPort string `env:"SRV_PORT" env-default:"8080"`
}

func MustRead() *Config {

	if err := godotenv.Load("../.env"); err != nil { // DEBUG:"../../.env"
		log.Print("INFO: file .env is not exists. Loading env variables ")
	}

	cfg := Config{}
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		help, _ := cleanenv.GetDescription(cfg, nil)
		log.Print(help)
		log.Fatal(err)
	}

	return &cfg
}
