package env

import (
	"context"
	"sync"

	"github.com/spf13/viper"
)

type Config struct {
	AppConfig AppConfig
}

type AppConfig struct {
	BOOST_LISTEN_ADDR string
	RELAY_URLS        string
	RELAY_TIMEOUT_MS  int64
	SENTRY_DSN        string
}

var (
	cfg Config

	onceDefaultClient sync.Once
)

func Read(ctx context.Context) (*Config, error) {
	var err error

	onceDefaultClient.Do(func() {
		viper.SetConfigName(".env")
		viper.SetConfigType("dotenv") // REQUIRED if the config file does not have the extension in the name
		viper.AddConfigPath(".")

		if err = viper.ReadInConfig(); err != nil {
			return
		}

		cfg = Config{
			AppConfig: AppConfig{
				BOOST_LISTEN_ADDR: viper.GetString("BOOST_LISTEN_ADDR"),
				RELAY_URLS:        viper.GetString("RELAY_URLS"),
				RELAY_TIMEOUT_MS:  viper.GetInt64("RELAY_TIMEOUT_MS"),
				SENTRY_DSN:        viper.GetString("SENTRY_DSN"),
			},
		}
	})

	return &cfg, err
}
