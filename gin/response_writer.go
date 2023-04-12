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
    logger    logging.Logger
    logPrefix string
}

func (r *ResponseWriter) Write(p []byte) (n int, err error) {
    var res map[string]any
    if err := json.Unmarshal(p, &res); err != nil {
        return r.ResponseWriter.Write(p)
    }
    for _, k := range r.KeysToSign {
        tmp, ok := res[k].(string)
        if !ok {
            continue
        }

        ciphertext, err := CBCEncrypt(tmp, r.CipherKey)
        if err != nil {
            r.logger.Warning(r.logPrefix, "failed to cbc encrypt: ", err.Error())
            continue
        }

        res[k] = ciphertext
    }
    r.logger.Debug(r.logPrefix, " before Write: ", res)
    raw, err := json.Marshal(res)
    if err != nil {
        return r.ResponseWriter.Write(p)
    }
    r.logger.Debug(r.logPrefix, " after Write: ", string(raw))
    return r.ResponseWriter.Write(raw)
}

