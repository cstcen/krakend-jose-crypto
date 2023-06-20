package gin

import jose "github.com/krakendio/krakend-jose/v2"

type Factory interface {
	jose.RejecterFactory
	CrypterFactory
}

type CrypterFactory interface {
	EncrypterFactory
	DecrypterFactory
}

type EncrypterFactory interface {
	NewEncrypter() Encrypter
}

type NoEncrypterFactory struct {
}

func (n *NoEncrypterFactory) NewEncrypter() Encrypter {
	return func(s string) (string, error) {
		return s, nil
	}
}

type DecrypterFactory interface {
	NewDecrypter() Decrypter
}

type NoDecrypterFactory struct {
}

func (n *NoDecrypterFactory) NewDecrypter() Decrypter {
	return func(s string) (string, error) {
		return s, nil
	}
}

type Encrypter func(plaintext string) (string, error)
type Decrypter func(ciphertext string) (string, error)
