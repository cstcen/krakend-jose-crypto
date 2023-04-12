package gin

import (
    "encoding/json"
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
    return TokenCrypto(joseGin.HandlerFactory(hf, logger, rejecterF), logger)
}

func TokenCrypto(hf luraGin.HandlerFactory, logger logging.Logger) luraGin.HandlerFactory {
    return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
        logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][JWTCrypto]"
        signerConfig, err := getSignerConfig(cfg)
        handler := hf(cfg, prxy)
        if err == jose.ErrNoSignerCfg {
            logger.Debug(logPrefix, "Crypto disabled")
            return handler
        }
        if err != nil {
            logger.Error(logPrefix, "Unable to create the Crypto:", err.Error())
            return func(c *gin.Context) {
                c.AbortWithStatus(http.StatusUnauthorized)
            }
        }

        logger.Debug(logPrefix, "Crypto enabled")

        return func(c *gin.Context) {

            c.Writer = &ResponseWriter{
                ResponseWriter: c.Writer,
                SignerConfig:   *signerConfig,
                logger:         logger,
                logPrefix: logPrefix,
            }

            decryptHeader(c, logPrefix, logger, signerConfig)

            handler(c)

        }
    }
}

func decryptHeader(c *gin.Context, logPrefix string, logger logging.Logger, signerConfig *jose.SignerConfig) {
    authInHeader := c.GetHeader("Authorization")
    prefix := "Bearer "
    ciphertext := strings.TrimPrefix(prefix, authInHeader)

    logger.Debug(logPrefix, "ciphertext: ", ciphertext)
    plaintext, err := CBCDecrypt(ciphertext, signerConfig.CipherKey)
    if err != nil {
        logger.Debug(logPrefix, "failed to cbc decrypt: ", err.Error())
        return
    }

    logger.Debug(logPrefix, "plaintext: ", plaintext)
    c.Header("Authorization", prefix + plaintext)
}

func getSignerConfig(cfg *config.EndpointConfig) (*jose.SignerConfig, error) {
    tmp, ok := cfg.ExtraConfig[jose.SignerNamespace]
    if !ok {
        return nil, jose.ErrNoSignerCfg
    }
    data, _ := json.Marshal(tmp)
    res := new(jose.SignerConfig)
    if err := json.Unmarshal(data, res); err != nil {
        return nil, err
    }
    return res, nil
}

