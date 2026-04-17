package service

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"

	"github.com/xiongwp/kms-manage/internal/keystore"
	"github.com/xiongwp/kms-manage/internal/metrics"
)

func init() { metrics.Register() }

func setupSvc(t *testing.T, active string, keys map[string]string) *KMSService {
	t.Helper()
	dir := t.TempDir()
	for name, hex := range keys {
		if err := os.WriteFile(filepath.Join(dir, name+".key"), []byte(hex), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "ACTIVE"), []byte(active), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := keystore.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return NewKMSService(s, zap.NewNop())
}

const (
	k1hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	k2hex = "ff020304050607080900000000000000ffffffffffffffffffffffffffffffff"
)

func TestEncryptDecrypt_UsesActive(t *testing.T) {
	svc := setupSvc(t, "main", map[string]string{"main": k1hex, "old": k2hex})

	out, err := svc.Encrypt(context.Background(), EncryptIn{
		Plaintext: []byte("secret-token-xxx"),
		Context:   "svc:pc:token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.KeyID != "main" {
		t.Fatalf("want main got %s", out.KeyID)
	}

	dec, err := svc.Decrypt(context.Background(), DecryptIn{
		Ciphertext: out.Ciphertext,
		Context:    "svc:pc:token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Plaintext, []byte("secret-token-xxx")) {
		t.Fatalf("plaintext lost: %q", dec.Plaintext)
	}
}

func TestDecrypt_OldKeyStillWorks(t *testing.T) {
	// 用 key "old" 加密，keystore 留着 old 和 main，active=main
	svc := setupSvc(t, "main", map[string]string{"main": k1hex, "old": k2hex})
	enc, err := svc.Encrypt(context.Background(), EncryptIn{
		KeyID:     "old",
		Plaintext: []byte("legacy"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if enc.KeyID != "old" {
		t.Fatalf("want old got %s", enc.KeyID)
	}
	// 用默认 active 解密 —— 但密文里带着 old，应该走 old
	dec, err := svc.Decrypt(context.Background(), DecryptIn{Ciphertext: enc.Ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	if dec.KeyID != "old" {
		t.Fatalf("decrypt should pick kid from envelope, got %s", dec.KeyID)
	}
}

func TestEncrypt_UnknownKeyID(t *testing.T) {
	svc := setupSvc(t, "main", map[string]string{"main": k1hex})
	_, err := svc.Encrypt(context.Background(), EncryptIn{KeyID: "ghost", Plaintext: []byte("x")})
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("want ErrKeyNotFound, got %v", err)
	}
}

func TestDecrypt_WrongContext(t *testing.T) {
	svc := setupSvc(t, "main", map[string]string{"main": k1hex})
	enc, _ := svc.Encrypt(context.Background(), EncryptIn{Plaintext: []byte("x"), Context: "a"})
	_, err := svc.Decrypt(context.Background(), DecryptIn{Ciphertext: enc.Ciphertext, Context: "b"})
	if err == nil {
		t.Fatal("wrong context must fail")
	}
}

func TestGenerateDataKey(t *testing.T) {
	svc := setupSvc(t, "main", map[string]string{"main": k1hex})
	out, err := svc.GenerateDataKey(context.Background(), GenerateDataKeyIn{Context: "bulk"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Plaintext) != 32 {
		t.Fatalf("dek size %d", len(out.Plaintext))
	}
	if out.KeyID != "main" {
		t.Fatalf("kid %s", out.KeyID)
	}
	// 解密 DEK 拿回来应该和明文一致
	dec, err := svc.Decrypt(context.Background(), DecryptIn{Ciphertext: out.Encrypted, Context: "bulk"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Plaintext, out.Plaintext) {
		t.Fatal("DEK round-trip lost")
	}
}

func TestGenerateDataKey_BadSize(t *testing.T) {
	svc := setupSvc(t, "main", map[string]string{"main": k1hex})
	_, err := svc.GenerateDataKey(context.Background(), GenerateDataKeyIn{Bytes: 9})
	if err == nil {
		t.Fatal("bytes=9 must be rejected")
	}
}

func TestListDescribe(t *testing.T) {
	svc := setupSvc(t, "main", map[string]string{"main": k1hex, "old": k2hex})
	list, active := svc.ListKeys()
	if active != "main" {
		t.Fatal(active)
	}
	if len(list) != 2 {
		t.Fatalf("len %d", len(list))
	}
	m, ok := svc.DescribeKey("main")
	if !ok || m.Algorithm != "AES-256-GCM" {
		t.Fatalf("describe %+v ok=%v", m, ok)
	}
}
