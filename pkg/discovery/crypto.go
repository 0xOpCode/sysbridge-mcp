package discovery

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
)

func GenerateKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func LoadOrCreateKey(path string) ([]byte, error) {
	expanded := config.ExpandPath(path)
	if expanded == "" {
		expanded = filepath.Join(config.UserConfigDir(), "secret.key")
	}

	if data, err := os.ReadFile(expanded); err == nil {
		trimmed := strings.TrimSpace(string(data))
		if keyBytes, decErr := hex.DecodeString(trimmed); decErr == nil && len(keyBytes) == 32 {
			return keyBytes, nil
		}
		if len(data) >= 32 {
			out := make([]byte, 32)
			copy(out, data[:32])
			return out, nil
		}
	}

	keyHex, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate secret key: %w", err)
	}

	dir := filepath.Dir(expanded)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create key dir %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(expanded, []byte(keyHex+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("write secret key %s: %w", expanded, err)
	}

	return hex.DecodeString(keyHex)
}

func Sign(payload []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func Verify(payload []byte, signature string, key []byte) bool {
	if len(key) == 0 || signature == "" {
		return false
	}
	expectedHex := Sign(payload, key)
	sigBytes, err1 := hex.DecodeString(strings.TrimSpace(signature))
	expectedBytes, err2 := hex.DecodeString(expectedHex)
	if err1 != nil || err2 != nil {
		return false
	}
	return hmac.Equal(sigBytes, expectedBytes)
}
