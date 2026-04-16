// Package service 实现 KMSService 的业务逻辑 —— 纯 Go，不依赖 gRPC。
package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/xiongwp/kms-manage/internal/cryptoenv"
	"github.com/xiongwp/kms-manage/internal/keystore"
	"github.com/xiongwp/kms-manage/internal/metrics"
)

// ErrKeyNotFound 指定的 key_id 不在 keystore 里。
var ErrKeyNotFound = errors.New("kms: key_id not found")

type KMSService struct {
	store  *keystore.Store
	logger *zap.Logger
}

func NewKMSService(store *keystore.Store, logger *zap.Logger) *KMSService {
	return &KMSService{store: store, logger: logger}
}

// EncryptIn/Out：gRPC server 把 proto 翻成这套 DTO，业务纯 Go。
type EncryptIn struct {
	KeyID     string
	Plaintext []byte
	Context   string
}
type EncryptOut struct {
	Ciphertext string
	KeyID      string
}

// Encrypt 没传 key_id 就用 active。
func (s *KMSService) Encrypt(_ context.Context, in EncryptIn) (*EncryptOut, error) {
	kid := in.KeyID
	if kid == "" {
		kid = s.store.ActiveKeyID()
	}
	key, ok := s.store.KeyByID(kid)
	if !ok {
		metrics.KMSOpTotal.WithLabelValues("encrypt", "no_key").Inc()
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
	}
	ct, err := cryptoenv.Encrypt(key, kid, in.Context, in.Plaintext)
	if err != nil {
		metrics.KMSOpTotal.WithLabelValues("encrypt", "err").Inc()
		return nil, err
	}
	metrics.KMSOpTotal.WithLabelValues("encrypt", "ok").Inc()
	return &EncryptOut{Ciphertext: ct, KeyID: kid}, nil
}

type DecryptIn struct {
	Ciphertext string
	Context    string
}
type DecryptOut struct {
	Plaintext []byte
	KeyID     string
}

// Decrypt 会把密文里带的 key_id 查 keystore；找不到就失败。
func (s *KMSService) Decrypt(_ context.Context, in DecryptIn) (*DecryptOut, error) {
	plain, kid, err := cryptoenv.Decrypt(s.store.Snapshot(), in.Ciphertext, in.Context)
	if err != nil {
		if kid != "" {
			metrics.KMSOpTotal.WithLabelValues("decrypt", "err").Inc()
		} else {
			metrics.KMSOpTotal.WithLabelValues("decrypt", "bad_format").Inc()
		}
		return nil, err
	}
	metrics.KMSOpTotal.WithLabelValues("decrypt", "ok").Inc()
	return &DecryptOut{Plaintext: plain, KeyID: kid}, nil
}

type GenerateDataKeyIn struct {
	KeyID   string
	Context string
	Bytes   int
}
type GenerateDataKeyOut struct {
	Plaintext    []byte
	Encrypted    string
	KeyID        string
}

// GenerateDataKey 产一个随机 DEK，并用 master key 加密返回。
// 调用方拿到明文 DEK 做本地字段加密后应该立即清零。
func (s *KMSService) GenerateDataKey(_ context.Context, in GenerateDataKeyIn) (*GenerateDataKeyOut, error) {
	n := in.Bytes
	if n == 0 {
		n = 32
	}
	switch n {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("kms: dek bytes must be 16/24/32, got %d", n)
	}

	kid := in.KeyID
	if kid == "" {
		kid = s.store.ActiveKeyID()
	}
	master, ok := s.store.KeyByID(kid)
	if !ok {
		metrics.KMSOpTotal.WithLabelValues("gen_dek", "no_key").Inc()
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
	}

	dek := make([]byte, n)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	encDek, err := cryptoenv.Encrypt(master, kid, in.Context, dek)
	if err != nil {
		metrics.KMSOpTotal.WithLabelValues("gen_dek", "err").Inc()
		return nil, err
	}
	metrics.KMSOpTotal.WithLabelValues("gen_dek", "ok").Inc()
	return &GenerateDataKeyOut{
		Plaintext: dek,
		Encrypted: encDek,
		KeyID:     kid,
	}, nil
}

// DescribeKey / ListKeys 用于管理面。

func (s *KMSService) DescribeKey(id string) (keystore.KeyMeta, bool) {
	return s.store.Meta(id)
}

func (s *KMSService) ListKeys() ([]keystore.KeyMeta, string) {
	return s.store.List(), s.store.ActiveKeyID()
}
