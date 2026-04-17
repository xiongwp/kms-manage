// Package cryptoenv 实现 kms-manage 的线格式密文 encode/decode。
//
// 对外只暴露两条规则：
//  1. 密文永远长这样：kms:v1:<key_id>:<base64url(nonce || ct || tag)>
//  2. AAD 永远是：    "kms/v1|" + key_id + "|" + context
//
// 这两条必须和 kmsclient 那边保持一致，一旦改动要同步两边。
package cryptoenv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	Prefix     = "kms:v1"
	NonceSize  = 12 // AES-GCM 默认 nonce 96-bit
	TagSize    = 16 // AES-GCM tag 128-bit
	AADVersion = "kms/v1"
)

var (
	ErrBadFormat   = errors.New("cryptoenv: ciphertext is not a kms:v1 envelope")
	ErrBadKeySize  = errors.New("cryptoenv: master key must be 16/24/32 bytes")
	ErrShortCipher = errors.New("cryptoenv: payload too short")
)

// aad 构造 GCM AAD：既锁定 key_id（拆不开篡改 keyid 后再解密），也锁定调用方给的 context。
func aad(keyID, context string) []byte {
	return []byte(AADVersion + "|" + keyID + "|" + context)
}

// ValidateKey 检查 master key 长度合法（AES-128/192/256）。
func ValidateKey(key []byte) error {
	switch len(key) {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("%w: got %d", ErrBadKeySize, len(key))
	}
}

// Encrypt 用给定 master key + key_id + context 把明文封成线格式密文。
// master key 字节数必须是 16/24/32，否则返回 ErrBadKeySize。
func Encrypt(key []byte, keyID, context string, plaintext []byte) (string, error) {
	if err := ValidateKey(key); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, aad(keyID, context))
	payload := make([]byte, 0, len(nonce)+len(sealed))
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)
	return Prefix + ":" + keyID + ":" + base64.RawURLEncoding.EncodeToString(payload), nil
}

// Decrypt 解码线格式密文并用 keys[key_id] 解密；context 必须和 Encrypt 时完全一致。
// keys 传的是 keystore 快照（key_id → raw bytes），由上层维护。
func Decrypt(keys map[string][]byte, ciphertext, context string) ([]byte, string, error) {
	keyID, payload, err := ParseEnvelope(ciphertext)
	if err != nil {
		return nil, "", err
	}
	key, ok := keys[keyID]
	if !ok {
		return nil, keyID, fmt.Errorf("cryptoenv: unknown key_id %q", keyID)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, keyID, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, keyID, err
	}
	if len(payload) < NonceSize+TagSize {
		return nil, keyID, ErrShortCipher
	}
	nonce, body := payload[:NonceSize], payload[NonceSize:]
	plain, err := gcm.Open(nil, nonce, body, aad(keyID, context))
	if err != nil {
		return nil, keyID, fmt.Errorf("cryptoenv: decrypt failed: %w", err)
	}
	return plain, keyID, nil
}

// ParseEnvelope 把 "kms:v1:<kid>:<b64>" 拆成 (kid, raw payload)。
// 不做解密，只做格式校验，让 admin 侧可以看谁的 key_id 在用。
func ParseEnvelope(s string) (keyID string, payload []byte, err error) {
	if !strings.HasPrefix(s, Prefix+":") {
		return "", nil, ErrBadFormat
	}
	rest := strings.TrimPrefix(s, Prefix+":")
	// rest = "<key_id>:<b64>"
	i := strings.IndexByte(rest, ':')
	if i <= 0 || i == len(rest)-1 {
		return "", nil, ErrBadFormat
	}
	keyID = rest[:i]
	b64 := rest[i+1:]
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrBadFormat, err)
	}
	return keyID, raw, nil
}

// IsCiphertext 判定一个字符串是不是 kms:v1 线格式密文。
// 不保证能解密，只是 cheap 前缀检查，用于"这字段是密文吗？"场景。
func IsCiphertext(s string) bool { return strings.HasPrefix(s, Prefix+":") }
