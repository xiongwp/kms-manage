// Service self-registration to etcd.
//
// kms-manage 启动期把 (service, host:grpc_port) 写到 etcd，调用方
//（payment-admin-web BFF / payment-core / accounting-system / ...）通过
// etcd resolver "etcd:///kms-manage" 拿到所有活副本 + round_robin LB。
//
// 此前 kms-manage 漏写了这一步，导致开启了 REGISTRY_ENDPOINTS 的调用方
// 在 etcd 里拿到 0 个端点，gRPC round_robin 无 SubConn，任何 RPC 直接报
//   rpc error: code = Unavailable desc = no children to pick from
// 现在通过 fx 生命周期注册：OnStart 写端点 + 续租；OnStop 主动 revoke
// lease 让端点立即从 etcd 摘掉，避免下游短期把流量打到正在退出的副本。
//
// registry.endpoints 留空时跳过自注册，调用方走直连 fallback（dev / 单实例）。
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
	"github.com/xiongwp/payment-util/serviceregistry"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

func startServiceRegistrar(lc fx.Lifecycle, v *viper.Viper, logger *zap.Logger) {
	endpoints := v.GetStringSlice("registry.endpoints")
	if len(endpoints) == 0 {
		logger.Info("registry.endpoints empty; skip etcd self-registration (callers must use direct addr)")
		return
	}
	service := v.GetString("registry.service_name")
	if service == "" {
		service = "kms-manage"
	}
	port := v.GetInt("server.grpc_port")
	if port == 0 {
		port = 9290
	}
	host := os.Getenv("REGISTRY_ADVERTISE_ADDR")
	if host == "" {
		host = v.GetString("registry.advertise_host")
	}
	if host == "" {
		if h, err := os.Hostname(); err == nil {
			host = h
		} else {
			host = "unknown"
		}
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	ttl := v.GetDuration("registry.ttl")
	if ttl < time.Second {
		ttl = 10 * time.Second
	}

	var sr *serviceregistry.SelfRegistration
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			regCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			r, err := serviceregistry.RegisterSelf(regCtx, endpoints, service, addr, ttl)
			if err != nil {
				// 不阻断启动：调用方仍可通过直连 fallback 工作，运维通过日志告警介入
				logger.Error("etcd self-registration failed", zap.Error(err),
					zap.String("service", service), zap.String("addr", addr),
					zap.Strings("etcd", endpoints))
				return nil
			}
			sr = r
			logger.Info("kms-manage registered to etcd",
				zap.String("service", service), zap.String("addr", addr),
				zap.Strings("etcd", endpoints), zap.Duration("ttl", ttl))
			return nil
		},
		OnStop: func(_ context.Context) error {
			if sr != nil {
				_ = sr.Close()
				logger.Info("kms-manage deregistered from etcd",
					zap.String("service", service), zap.String("addr", addr))
			}
			return nil
		},
	})
}
