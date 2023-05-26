package gin

import (
	"fmt"
	"github.com/gin-gonic/gin"
	jose "github.com/krakendio/krakend-jose/v2"
	joseGin "github.com/krakendio/krakend-jose/v2/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	luraGin "github.com/luraproject/lura/v2/router/gin"
	"net/http"
	"strings"
)

func HandlerFactory(hf luraGin.HandlerFactory, logger logging.Logger, rejecterF jose.RejecterFactory) luraGin.HandlerFactory {
	return Decrypt(Encrypt(joseGin.HandlerFactory(hf, logger, rejecterF), logger), logger)
}

func Encrypt(hf luraGin.HandlerFactory, logger logging.Logger) luraGin.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][JWTEncrypt]"
		encryptCfg, err := GetEncryptCfg(cfg)
		if err != nil {
			return nil
		}
		handler := hf(cfg, prxy)
		if err == ErrNoEncryptCfg {
			logger.Debug(logPrefix, "Encrypt disabled")
			return handler
		}
		if err != nil {
			logger.Error(logPrefix, "Unable to create the Encrypt:", err.Error())
			return func(c *gin.Context) {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
		}

		logger.Debug(logPrefix, "Encrypt enabled")

		return func(c *gin.Context) {

			encryptor := func(content string) (string, error) {
				cipherKey := encryptCfg.CipherKey
				logger.Debug(logPrefix, "cipher key: ", fmt.Sprintf("%s", cipherKey))
				return CFBEncrypt(content, cipherKey)
			}
			keysToSign := encryptCfg.KeysToSign
			c.Writer = &ResponseWriter{
				ResponseWriter: c.Writer,
				KeysToSign:     keysToSign,
				logger:         logger,
				logPrefix:      logPrefix,
				encryptor:      encryptor,
			}

			handler(c)

			// location := c.GetHeader("Location")
			// logger.Debug(logger, "location: ", location)
			// lUrl, err := url.Parse(location)
			// if err != nil {
			// 	return
			// }

			// fragments := strings.Split(lUrl.Fragment, "&")
			// for _, keyToSign := range keysToSign {
			// 	for i, fragment := range fragments {
			// 		key, val, found := strings.Cut(fragment, "=")
			// 		if !found {
			// 			continue
			// 		}
			// 		if keyToSign == key {
			// 			enVal, err := encryptor(val)
			// 			if err != nil {
			// 				logger.Warning(logPrefix, "key: "+key, "encrypt err: "+err.Error())
			// 				continue
			// 			}
			// 			fragments[i] = enVal
			// 		}
			// 	}
			// }
			//
			// lUrl.Fragment = strings.Join(fragments, "&")
		}
	}
}

func Decrypt(hf luraGin.HandlerFactory, logger logging.Logger) luraGin.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][JWTDecrypt]"
		decryptCfg, err := GetDecryptCfg(cfg)
		handler := hf(cfg, prxy)
		if err == ErrNoDecryptCfg {
			logger.Debug(logPrefix, "Decrypt disabled")
			return handler
		}
		if err != nil {
			logger.Error(logPrefix, "Unable to create the Decrypt:", err.Error())
			return func(c *gin.Context) {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
		}

		logger.Debug(logPrefix, "Decrypt enabled")

		return func(c *gin.Context) {

			prefix := "Bearer "
			ciphertext := strings.TrimPrefix(c.GetHeader("Authorization"), prefix)

			logger.Debug(logPrefix, "ciphertext: ", ciphertext)
			plaintext, err := CFBDecrypt(ciphertext, decryptCfg.CipherKey)
			if err != nil {
				logger.Debug(logPrefix, "failed to decrypt: ", err.Error())
				return
			}

			logger.Debug(logPrefix, "plaintext: ", plaintext)
			c.Request.Header.Set("Authorization", prefix+plaintext)

			handler(c)

		}
	}
}
