package gin

import (
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

			authInHeader := c.GetHeader("Authorization")
			prefix := "Bearer "
			ciphertext := strings.TrimPrefix(authInHeader, prefix)

			logger.Debug(logPrefix, "ciphertext: ", ciphertext)
			plaintext, err := CBCDecrypt(ciphertext, signatureConfig.CipherKey)
			if err != nil {
				logger.Debug(logPrefix, "failed to cbc decrypt: ", err.Error())
				return
			}

			logger.Debug(logPrefix, "plaintext: ", plaintext)
			c.Header("Authorization", prefix+plaintext)

			handler(c)

		}
	}
}
