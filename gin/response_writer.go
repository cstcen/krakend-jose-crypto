package gin

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	jose "github.com/krakendio/krakend-jose/v2"
	"github.com/luraproject/lura/v2/logging"
)

type ResponseWriter struct {
	gin.ResponseWriter
	jose.SignerConfig
	logger     logging.Logger
	logPrefix  string
	encrypterF EncrypterFactory
}

func (r *ResponseWriter) Write(p []byte) (n int, err error) {
	var res map[string]any
	if err := json.Unmarshal(p, &res); err != nil {
		return r.ResponseWriter.Write(p)
	}
	// cipherKey := r.CipherKey
	// r.logger.Debug(r.logPrefix, "cipher key: ", fmt.Sprintf("%s", cipherKey))
	encrypter := r.encrypterF.NewEncrypter()
	for _, k := range r.KeysToSign {
		tmp, ok := res[k].(string)
		if !ok {
			r.logger.Warning(r.logPrefix, "failed to convert to string, key: ", k)
			continue
		}

		ciphertext, err := encrypter.Encrypt(tmp)
		if err != nil {
			r.logger.Warning(r.logPrefix, "failed to encrypt: ", err.Error())
			continue
		}

		res[k] = ciphertext
	}
	r.logger.Debug(r.logPrefix, " Write: ", res)
	raw, err := json.Marshal(res)
	if err != nil {
		return r.ResponseWriter.Write(p)
	}
	return r.ResponseWriter.Write(raw)
}
