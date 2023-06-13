package gin

import (
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	jose "github.com/krakendio/krakend-jose/v2"
	joseGin "github.com/krakendio/krakend-jose/v2/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	luraGin "github.com/luraproject/lura/v2/router/gin"
	"io"
	"net/http"
	"strings"
)

func HandlerFactory(hf luraGin.HandlerFactory, logger logging.Logger, rejecterF jose.RejecterFactory) luraGin.HandlerFactory {
	return Decrypt(Encrypt(joseGin.HandlerFactory(hf, logger, rejecterF), logger), logger)
}

func Encrypt(hf luraGin.HandlerFactory, logger logging.Logger) luraGin.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][JWTEncrypt]"
		signerConfig, _, err := jose.NewSigner(cfg, nil)
		handler := hf(cfg, prxy)
		if err == jose.ErrNoSignerCfg {
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

			c.Writer = &ResponseWriter{
				ResponseWriter: c.Writer,
				SignerConfig:   *signerConfig,
				logger:         logger,
				logPrefix:      logPrefix,
			}

			handler(c)

		}
	}
}

func Decrypt(hf luraGin.HandlerFactory, logger logging.Logger) luraGin.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][JWTDecrypt]"
		signatureConfig, err := jose.GetSignatureConfig(cfg)
		handler := hf(cfg, prxy)
		if err == jose.ErrNoValidatorCfg {
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
			if len(ciphertext) == 0 {
				handler(c)
				return
			}
			cipherKey := signatureConfig.CipherKey
			plaintext, err := CFBDecrypt(ciphertext, cipherKey)
			if err != nil {
				logger.Debug(logPrefix, "failed to decrypt: ", err.Error())
				handler(c)
				return
			}

			logger.Debug(logPrefix, "plaintext: ", plaintext)
			req := c.Request
			req.Header.Set("Authorization", prefix+plaintext)

			if req.Body != nil {
				if decryptBody(c, req, handler, cipherKey) {
					return
				}
			}

			handler(c)

		}
	}
}

func decryptBody(c *gin.Context, req *http.Request, handler gin.HandlerFunc, cipherKey []byte) bool {
	var result map[string]any
	if err := json.NewDecoder(req.Body).Decode(&result); err != nil {
		handler(c)
		return true
	}
	req.Body.Close()
	keysToSign := []string{"access_token", "refresh_token"}
	for _, k := range keysToSign {
		ciphertext, ok := result[k].(string)
		if !ok {
			continue
		}
		plaintext, err := CFBDecrypt(ciphertext, cipherKey)
		if err != nil {
			handler(c)
			return true
		}
		result[k] = plaintext
	}

	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(result); err != nil {
		handler(c)
		return true
	}
	req.Body = io.NopCloser(buf)
	return false
}
