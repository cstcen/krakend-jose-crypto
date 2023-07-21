package gin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/auth0-community/go-auth0"
	"github.com/buger/jsonparser"
	"github.com/gin-gonic/gin"
	jose "github.com/krakendio/krakend-jose/v2"
	joseGin "github.com/krakendio/krakend-jose/v2/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	luraGin "github.com/luraproject/lura/v2/router/gin"
	"gopkg.in/square/go-jose.v2/jwt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

const (
	DecryptNamespace = "github.com/cstcen/krakend-jose-crypto/decrypt"
	EncryptNamespace = "github.com/cstcen/krakend-jose-crypto/encrypt"
	defaultRolesKey  = "roles"
)

func HandlerFactory(hf luraGin.HandlerFactory, logger logging.Logger, factory Factory) luraGin.HandlerFactory {
	return TokenSignatureValidator(TokenSigner(joseGin.HandlerFactory(hf, logger, factory), logger, factory), logger, factory, factory)
}

func TokenSigner(hf luraGin.HandlerFactory, logger logging.Logger, encrypterF EncrypterFactory) luraGin.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][JWTSigner]"
		signerCfg, signer, err := jose.NewSigner(cfg, nil)
		if err == jose.ErrNoSignerCfg {
			logger.Debug(logPrefix, "Signer disabled")
			return hf(cfg, prxy)
		}
		if err != nil {
			logger.Error(logPrefix, "Unable to create the signer:", err.Error())
			return erroredHandler
		}

		if encrypterF == nil {
			encrypterF = new(NoEncrypterFactory)
		}
		encrypter := encrypterF.NewEncrypter()

		logger.Debug(logPrefix, "Signer enabled")

		return func(c *gin.Context) {
			proxyReq := luraGin.NewRequest(cfg.HeadersToPass)(c, cfg.QueryString)
			ctx, cancel := context.WithTimeout(c, cfg.Timeout)
			defer cancel()

			response, err := prxy(ctx, proxyReq)
			if err != nil {
				logger.Error(logPrefix, "Proxy response:", err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if response == nil {
				logger.Error(logPrefix, "Empty proxy response")
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			if err := SignFields(signerCfg.KeysToSign, Signer(signer, encrypter), response); err != nil {
				logger.Error(logPrefix, "Signing fields:", err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			for k, v := range response.Metadata.Headers {
				c.Header(k, v[0])
			}
			c.JSON(response.Metadata.StatusCode, response.Data)
		}
	}
}

func TokenSignatureValidator(hf luraGin.HandlerFactory, logger logging.Logger, rejecterF jose.RejecterFactory, decrypterF DecrypterFactory) luraGin.HandlerFactory {
	return func(cfg *config.EndpointConfig, prxy proxy.Proxy) gin.HandlerFunc {
		logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][JWTValidator]"
		if rejecterF == nil {
			rejecterF = new(jose.NopRejecterFactory)
		}
		rejecter := rejecterF.New(logger, cfg)
		if decrypterF == nil {
			decrypterF = new(NoDecrypterFactory)
		}
		decrypter := decrypterF.NewDecrypter()

		handler := hf(cfg, prxy)
		scfg, err := GetSignatureConfig(cfg)
		if err == jose.ErrNoValidatorCfg {
			logger.Info(logPrefix, "Validator disabled for this endpoint")
			return handler
		}
		if err != nil {
			logger.Warning(logPrefix, "Unable to parse the configuration:", err.Error())
			return erroredHandler
		}

		validator, err := jose.NewValidator(&scfg.SignatureConfig, FromBody(scfg.IsRefreshToken, scfg.TokenKeyInBody))
		if err != nil {
			logger.Fatal(logPrefix, "Unable to create the validator:", err.Error())
			return erroredHandler
		}

		var aclCheck func(string, map[string]interface{}, []string) bool

		if scfg.RolesKeyIsNested && strings.Contains(scfg.RolesKey, ".") && scfg.RolesKey[:4] != "http" {
			logger.Debug(logPrefix, fmt.Sprintf("Roles will be matched against the nested key: '%s'", scfg.RolesKey))
			aclCheck = jose.CanAccessNested
		} else {
			logger.Debug(logPrefix, fmt.Sprintf("Roles will be matched against the key: '%s'", scfg.RolesKey))
			aclCheck = jose.CanAccess
		}

		var scopesMatcher func(string, map[string]interface{}, []string) bool

		if len(scfg.Scopes) > 0 && scfg.ScopesKey != "" {
			if scfg.ScopesMatcher == "all" {
				logger.Debug(logPrefix, fmt.Sprintf("Constraint added: tokens must contain a claim '%s' with all these scopes: %v", scfg.ScopesKey, scfg.Scopes))
				scopesMatcher = jose.ScopesAllMatcher
			} else {
				logger.Debug(logPrefix, fmt.Sprintf("Constraint added: tokens must contain a claim '%s' with any of these scopes: %v", scfg.ScopesKey, scfg.Scopes))
				scopesMatcher = jose.ScopesAnyMatcher
			}
		} else {
			logger.Debug(logPrefix, "No scope validation required")
			scopesMatcher = jose.ScopesDefaultMatcher
		}

		if scfg.OperationDebug {
			logger.Debug(logPrefix, "Validator enabled for this endpoint. Operation debug is enabled")
		} else {
			logger.Debug(logPrefix, "Validator enabled for this endpoint")
		}

		paramExtractor := extractRequiredJWTClaims(cfg)

		return func(c *gin.Context) {
			if scfg.IsRefreshToken {
				if c.Request.Body == nil {
					if scfg.OperationDebug {
						logger.Error(logPrefix, "Unable to validate the refresh token: empty body")
					}
					c.AbortWithStatus(http.StatusUnauthorized)
					return
				}
				reqBody, _ := io.ReadAll(c.Request.Body)
				if _, err := jsonparser.GetString(reqBody, "refresh_token"); err != nil {
					c.Request.Body = io.NopCloser(bytes.NewReader(reqBody))
					handler(c)
					return
				}
				reqBody = decryptFromBody(decrypter, reqBody, scfg.TokenKeyInBody)
				c.Request.ContentLength = int64(len(reqBody))
				c.Request.Body = io.NopCloser(bytes.NewReader(reqBody))
			}
			decryptFromHeader(c, decrypter)
			decryptFromCookie(c, scfg, decrypter)

			token, err := validator.ValidateRequest(c.Request)
			if err != nil {
				if scfg.OperationDebug {
					logger.Error(logPrefix, "Unable to validate the token:", err.Error())
				}
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			claims := map[string]interface{}{}
			err = validator.Claims(c.Request, token, &claims)
			if err != nil {
				if scfg.OperationDebug {
					logger.Error(logPrefix, "Token sent by client is invalid:", err.Error())
				}
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			if rejecter.Reject(claims) {
				if scfg.OperationDebug {
					logger.Error(logPrefix, "Token sent by client rejected")
				}
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			if !aclCheck(scfg.RolesKey, claims, scfg.Roles) {
				if scfg.OperationDebug {
					logger.Error(logPrefix, "Token sent by client does not have sufficient roles")
				}
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			if !scopesMatcher(scfg.ScopesKey, claims, scfg.Scopes) {
				if scfg.OperationDebug {
					logger.Error(logPrefix, "Token sent by client does not have the required scopes")
				}
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			propagateHeaders(cfg, scfg.PropagateClaimsToHeader, claims, c, logger)

			paramExtractor(c, claims)

			handler(c)
		}
	}
}

type SignatureConfig struct {
	jose.SignatureConfig
	IsRefreshToken bool   `json:"is_refresh_token,omitempty"`
	TokenKeyInBody string `json:"token_key_in_body,omitempty"`
}

func GetSignatureConfig(cfg *config.EndpointConfig) (*SignatureConfig, error) {
	tmp, ok := cfg.ExtraConfig[jose.ValidatorNamespace]
	if !ok {
		return nil, jose.ErrNoValidatorCfg
	}
	data, _ := json.Marshal(tmp)
	res := new(SignatureConfig)
	if err := json.Unmarshal(data, res); err != nil {
		return nil, err
	}

	if res.RolesKey == "" {
		res.RolesKey = defaultRolesKey
	}
	if !strings.HasPrefix(res.URI, "https://") && !res.DisableJWKSecurity {
		return res, jose.ErrInsecureJWKSource
	}
	return res, nil
}

func Signer(signer jose.Signer, encrypter Encrypter) jose.Signer {
	return func(token interface{}) (string, error) {
		tmp, err := signer(token)
		if err != nil {
			return "", err
		}
		return encrypter.Encrypt(tmp)
	}
}

func SignFields(keys []string, signer jose.Signer, response *proxy.Response) error {
	src, err := json.Marshal(response.Data)
	if err != nil {
		return err
	}
	var dst = src

	paths := make([][]string, len(keys))
	for i, key := range keys {
		path := strings.Split(key, ".")
		paths[i] = path
	}

	jsonparser.EachKey(src, func(idx int, value []byte, vt jsonparser.ValueType, err error) {
		if err != nil {
			return
		}
		token, err := signer(value)
		if err != nil {
			return
		}
		tmp, err := jsonparser.Set(dst, []byte(fmt.Sprintf("%q", token)), paths[idx]...)
		if err != nil {
			return
		}
		dst = tmp
	}, paths...)

	if err := json.Unmarshal(dst, &response.Data); err != nil {
		return err
	}
	return nil
}

func FromBody(isRefreshToken bool, refreshTokenKey string) jose.ExtractorFactory {
	return func(key string) func(r *http.Request) (*jwt.JSONWebToken, error) {
		if !isRefreshToken {
			return joseGin.FromCookie(key)
		}

		return func(r *http.Request) (*jwt.JSONWebToken, error) {
			if r.Body == nil {
				return nil, auth0.ErrTokenNotFound
			}

			var reqBuf bytes.Buffer
			reqTee := io.TeeReader(r.Body, &reqBuf)
			reqBody, _ := io.ReadAll(reqTee)
			r.Body = io.NopCloser(&reqBuf)
			token, _ := jsonparser.GetString(reqBody, refreshTokenKey)
			return jwt.ParseSigned(token)
		}
	}
}

func decryptFromBody(decrypter Decrypter, reqBody []byte, tokenKeyInBody string) []byte {
	if len(tokenKeyInBody) == 0 {
		return reqBody
	}
	token, _ := jsonparser.GetString(reqBody, tokenKeyInBody)
	tk, err := decrypter.Decrypt(token)
	if err != nil {
		return reqBody
	}
	raw, err := jsonparser.Set(reqBody, []byte(fmt.Sprintf("%q", tk)), tokenKeyInBody)
	if err != nil {
		return reqBody
	}
	return raw
}

func decryptFromCookie(c *gin.Context, scfg *SignatureConfig, decrypter Decrypter) {
	cookie, err := c.Request.Cookie(scfg.CookieKey)
	if err != nil || len(cookie.Value) == 0 {
		return
	}
	tk, err := decrypter.Decrypt(cookie.Value)
	if err != nil {
		return
	}
	c.SetCookie(cookie.Name, tk, cookie.MaxAge, cookie.Path, cookie.Domain, cookie.Secure, cookie.HttpOnly)
}

func decryptFromHeader(c *gin.Context, decrypter Decrypter) {
	token := strings.TrimPrefix(c.Request.Header.Get("Authorization"), "Bearer ")
	if len(token) == 0 {
		return
	}
	tk, err := decrypter.Decrypt(token)
	if err != nil {
		return
	}
	c.Request.Header.Set("Authorization", "Bearer "+tk)
}

func erroredHandler(c *gin.Context) {
	c.AbortWithStatus(http.StatusUnauthorized)
}

func propagateHeaders(cfg *config.EndpointConfig, propagationCfg [][]string, claims map[string]interface{}, c *gin.Context, logger logging.Logger) {
	logPrefix := "[ENDPOINT: " + cfg.Endpoint + "][PropagateHeaders]"
	if len(propagationCfg) > 0 {
		headersToPropagate, err := jose.CalculateHeadersToPropagate(propagationCfg, claims)
		if err != nil {
			logger.Warning(logPrefix, err.Error())
		}
		for k, v := range headersToPropagate {
			// Set header value - replaces existing one
			c.Request.Header.Set(k, v)
		}
	}
}

var jwtParamsPattern = regexp.MustCompile(`{{\.JWT\.([^}]*)}}`)

func extractRequiredJWTClaims(cfg *config.EndpointConfig) func(*gin.Context, map[string]interface{}) {
	var required []string

	for _, backend := range cfg.Backend {
		for _, match := range jwtParamsPattern.FindAllStringSubmatch(backend.URLPattern, -1) {
			if len(match) < 2 {
				continue
			}
			required = append(required, match[1])
		}
	}
	if len(required) == 0 {
		return func(_ *gin.Context, _ map[string]interface{}) {}
	}

	return func(c *gin.Context, claims map[string]interface{}) {
		cl := jose.Claims(claims)
		for _, param := range required {
			// TODO: check for nested claims
			v, ok := cl.Get(param)
			if !ok {
				continue
			}
			c.Params = append(c.Params, gin.Param{Key: "JWT." + param, Value: v})
		}
	}
}

func GetRequestBody(req *http.Request) []byte {
	var reqBody []byte
	if req.Body == nil {
		return reqBody
	}
	var reqBuf bytes.Buffer
	reqTee := io.TeeReader(req.Body, &reqBuf)
	reqBody, _ = io.ReadAll(reqTee)
	req.Body = io.NopCloser(&reqBuf)
	return reqBody
}
