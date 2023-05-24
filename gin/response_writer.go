package gin

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/luraproject/lura/v2/logging"
)

type ResponseWriter struct {
	gin.ResponseWriter
	KeysToSign []string `json:"keys_to_sign,omitempty"`
	logger     logging.Logger
	logPrefix  string
	cipherKey  []byte
}

func (r *ResponseWriter) Write(p []byte) (n int, err error) {
	var res map[string]any
	if err := json.Unmarshal(p, &res); err != nil {
		return r.ResponseWriter.Write(p)
	}
	for _, k := range r.KeysToSign {
		tmp, ok := res[k].(string)
		if !ok {
			r.logger.Warning(r.logPrefix, "failed to convert to string, key: ", k)
			continue
		}

		r.logger.Debug(r.logPrefix, "cipher key: ", fmt.Sprintf("%s", r.cipherKey))
		ciphertext, err := CFBEncrypt(tmp, r.cipherKey)
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
