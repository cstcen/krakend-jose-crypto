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
	return &encrypt{}
}

type DecrypterFactory interface {
	NewDecrypter() Decrypter
}

type NoDecrypterFactory struct {
}

func (n *NoDecrypterFactory) NewDecrypter() Decrypter {
	return &decrypt{}
}

type Encrypter interface {
	Encrypt(plaintext string) (string, error)
}

type encrypt struct {
}

func (e *encrypt) Encrypt(plaintext string) (string, error) {
	return plaintext, nil
}

type Decrypter interface {
	Decrypt(ciphertext string) (string, error)
}

type decrypt struct {
}

func (e *decrypt) Decrypt(ciphertext string) (string, error) {
	return ciphertext, nil
}
