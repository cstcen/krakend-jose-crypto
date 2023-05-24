package gin

import (
	"encoding/json"
	"errors"
	"github.com/luraproject/lura/v2/config"
)

const (
	EncryptNamespace = "github.com/cstcen/krakend-jose-crypto/encrypt"
	DecryptNamespace = "github.com/cstcen/krakend-jose-crypto/decrypt"
)

var (
	ErrNoEncryptCfg = errors.New("no encrypt config")
	ErrNoDecryptCfg = errors.New("no decrypt config")
)

type EncryptConfig struct {
	KeysToSign []string `json:"keys_to_sign,omitempty"`
	CipherKey  []byte   `json:"cipher_key,omitempty"`
}

func GetEncryptCfg(cfg *config.EndpointConfig) (*EncryptConfig, error) {
	tmp, ok := cfg.ExtraConfig[EncryptNamespace]
	if !ok {
		return nil, ErrNoEncryptCfg
	}
	data, _ := json.Marshal(tmp)
	c := new(EncryptConfig)
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	return c, nil
}

type DecryptConfig struct {
	CipherKey []byte `json:"cipher_key,omitempty"`
}

func GetDecryptCfg(cfg *config.EndpointConfig) (*DecryptConfig, error) {
	tmp, ok := cfg.ExtraConfig[DecryptNamespace]
	if !ok {
		return nil, ErrNoDecryptCfg
	}
	data, _ := json.Marshal(tmp)
	c := new(DecryptConfig)
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	return c, nil
}
