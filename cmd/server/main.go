// Command server 启动 kms-manage gRPC 服务。
package main

import (
	"context"
	"errors"
	"strings"
	"os"

	"github.com/spf13/viper"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/xiongwp/kms-manage/internal/keystore"
	"github.com/xiongwp/kms-manage/internal/metrics"
	"github.com/xiongwp/kms-manage/internal/server"
	"github.com/xiongwp/kms-manage/internal/service"
)

func main() {
	metrics.Register()
	app := fx.New(
		fx.Provide(
			loadConfig,
			newLogger,
			newKeystore,
			newKMSSvc,
			newServer,
		),
		fx.Invoke(startGRPC, startMetricsHTTP),
	)
	app.Run()
}

func loadConfig() (*viper.Viper, error) {
	v := viper.New()
	v.SetEnvPrefix("KMS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./config")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/kms-manage")
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, err
		}
	}
	return v, nil
}

func newLogger() (*zap.Logger, error) {
	if os.Getenv("KMS_LOG_DEV") == "true" {
		return zap.NewDevelopment()
	}
	return zap.NewProduction()
}

func newKeystore(v *viper.Viper, logger *zap.Logger) (*keystore.Store, error) {
	dir := v.GetString("keystore.dir")
	if dir == "" {
		dir = "/var/lib/kms-manage/keys"
	}
	s, err := keystore.Load(dir)
	if err != nil {
		return nil, err
	}
	logger.Info("keystore loaded",
		zap.String("dir", dir),
		zap.String("active_key", s.ActiveKeyID()),
		zap.Int("total_keys", len(s.List())),
	)
	return s, nil
}

func newKMSSvc(s *keystore.Store, logger *zap.Logger) *service.KMSService {
	return service.NewKMSService(s, logger)
}

func newServer(svc *service.KMSService, v *viper.Viper, logger *zap.Logger) *server.Server {
	tokens := map[string]string{}
	for _, t := range v.GetStringSlice("auth.tokens") {
		tokens[t] = "ok"
	}
	return server.NewServer(server.Deps{
		KMSSvc:       svc,
		AuthTokens:   tokens,
		RateLimitRPS: v.GetFloat64("rate_limit.rps"),
		RateBurst:    v.GetInt("rate_limit.burst"),
		Logger:       logger,
	})
}

func startGRPC(lc fx.Lifecycle, s *server.Server, v *viper.Viper, logger *zap.Logger) {
	port := v.GetInt("server.grpc_port")
	if port == 0 {
		port = 9290
	}
	ctx, cancel := context.WithCancel(context.Background())
	lc.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			go func() {
				if err := s.ListenAndServe(ctx, port); err != nil {
					logger.Error("grpc exited", zap.Error(err))
				}
			}()
			return nil
		},
		OnStop: func(_ context.Context) error { cancel(); return nil },
	})
}

func startMetricsHTTP(lc fx.Lifecycle, v *viper.Viper, logger *zap.Logger) {
	addr := v.GetString("metrics.addr")
	if addr == "" {
		addr = ":9390"
	}
	lc.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			metrics.StartServer(addr, logger)
			return nil
		},
	})
}

// 静态分析别挑 time 没被用
