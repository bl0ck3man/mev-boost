package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/evalphobia/logrus_sentry"
	"github.com/flashbots/mev-boost/internal/env"
	"github.com/flashbots/mev-boost/server"
	"github.com/sirupsen/logrus"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var logger = logrus.StandardLogger()
	logger.SetFormatter(&logrus.JSONFormatter{})
	log := logger.WithContext(ctx)

	cfg, envErr := env.Read(ctx)
	if envErr != nil {
		println("Read env error:", envErr.Error())

		os.Exit(1)
	}

	hook, err := logrus_sentry.NewSentryHook(cfg.AppConfig.SENTRY_DSN, []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.InfoLevel,
		logrus.WarnLevel,
	})
	if err != nil {
		println(`Could not connect to sentry`)
		os.Exit(1)
	}

	logrus.AddHook(hook)

	relays := parseRelayURLs(cfg.AppConfig.RELAY_URLS)
	if len(relays) == 0 {
		log.Fatal("No relays specified")
	}
	log.WithField("relays", relays).Infof("using %d relays", len(relays))

	relayTimeout := time.Duration(cfg.AppConfig.RELAY_TIMEOUT_MS) * time.Millisecond
	server, err := server.NewBoostService(cfg.AppConfig.BOOST_LISTEN_ADDR, relays, log, relayTimeout)
	if err != nil {
		log.WithError(err).Fatal("failed creating the server")
	}

	log.Println("listening on", cfg.AppConfig.BOOST_LISTEN_ADDR)
	log.Fatal(server.StartHTTPServer())
}

func parseRelayURLs(relayURLs string) []server.RelayEntry {
	ret := []server.RelayEntry{}
	for _, entry := range strings.Split(relayURLs, ",") {
		relay, err := server.NewRelayEntry(entry)
		if err != nil {
			println(fmt.Sprintf(`Invalid relay URL %s`, entry))
			continue
		}
		ret = append(ret, relay)
	}
	return ret
}
