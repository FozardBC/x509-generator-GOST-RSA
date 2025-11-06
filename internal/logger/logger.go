package logger

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"os"

	"gopkg.in/natefinch/lumberjack.v2"
)

var fileLogWriter *lumberjack.Logger

const (
	LevelDebug = "debug"
	LevelDev   = "dev"
	LevelInfo  = "info"
)

func New(level string) *slog.Logger {
	var log *slog.Logger

	timestamp := time.Now().Format("02-01-2006_15:04")

	fileLogWriter = &lumberjack.Logger{
		Filename:   fmt.Sprintf("./logs/%s.log", timestamp),
		MaxSize:    10,
		MaxBackups: 3,
		Compress:   true,
	}

	multiWriter := io.MultiWriter(os.Stdout, fileLogWriter)

	switch level {
	case LevelDebug:
		log = slog.New(slog.NewJSONHandler(multiWriter, &slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: true,
		}))

	case LevelDev:
		log = slog.New(slog.NewJSONHandler(multiWriter, &slog.HandlerOptions{
			Level:     slog.LevelInfo,
			AddSource: true,
		}))
	case LevelInfo:
		log = slog.New(slog.NewJSONHandler(multiWriter, &slog.HandlerOptions{
			Level:     slog.LevelInfo,
			AddSource: false,
		}))
	}

	return log
}

func Close() error {
	if err := fileLogWriter.Close(); err != nil {
		return fmt.Errorf("failed to close Log file:%w", err)
	}

	return nil
}
