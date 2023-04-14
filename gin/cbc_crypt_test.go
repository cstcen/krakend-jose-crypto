package gin

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	key        = []byte("TEST JOSE CYPHER")
	content    = "eyJhbGciOiJIUzI1NiIsImtpZCI6InNpbTIifQ.eyJhdWQiOiJodHRwczovL2FwaS54azUuY29tL2dhdGV3YXkvdjIuMCIsImV4cCI6MTY4MTI4ODIwNiwiaWF0IjoxNjgxMjY2NjA2LCJpc3MiOiJodHRwczovL2FwaS54azUuY29tIiwic3ViIjoiYSJ9.NYag7rS7yVlUjdcLQ_dRn7sk0DOET5kvkhG8wvIzgjs"
	ciphertext = "daaabfae7e74c92bb719d0159ba70506a99cd1538e89f96da71f60af1a6f9d374ee8fdf49e97b920b7c4f15d4f3578b1aebd59fc2c1f8f810d17207abb44b3bdec142b60f03f5b1e47e94f646f675ee4a32bfdd919349f5306a627da29b0c41061ea840ebb6d37fb693462fedfc84bfcc4a6e23ec4235db6f033869f49a7c85d5312099a0b75a2d7d504cd619a68bb5a8797a6c48d1f792194b936e3de72931edf58f62c7322750ba8576f359fb298dccb33d83bb4fdc5be9e0ed0b76ba22af5266e344d11ae6b38af0a8e2684bfd5ca1a14bac9978c26ce9cc83de86a118366e36e7a39755fa8a3e529b796943138deb18b42814e32c3767ce3b2"
)

func TestBase64Key(t *testing.T) {
	e := base64.StdEncoding.EncodeToString(key)
	fmt.Printf("%s\n", e)
	d, _ := base64.StdEncoding.DecodeString(e)
	fmt.Printf("%s\n", d)
}

func TestCBCEncrypt(t *testing.T) {
	type args struct {
		content string
		key     []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "encrypt", args: args{
			content: content,
			key:     []byte(hex.EncodeToString(key)),
		}, want: "", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CBCEncrypt(tt.args.content, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("CBCEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CBCEncrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCBCDecrypt(t *testing.T) {
	type args struct {
		content string
		key     []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "decrypt", args: args{
			content: "",
			key:     key,
		}, want: "", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CBCDecrypt(tt.args.content, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("CBCDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CBCDecrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCFBEncrypt(t *testing.T) {
	type args struct {
		content string
		key     []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "cfb en", args: args{
			content: content,
			key:     []byte(base64.StdEncoding.EncodeToString(key)),
		}, want: ciphertext, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CFBEncrypt(tt.args.content, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("CFBEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.NotEmpty(t, got)
			t.Log("got = ", got)
		})
	}
}

func TestCFBDecrypt(t *testing.T) {
	type args struct {
		content string
		key     []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "cfb de", args: args{
			content: "749915a78131407be5285324e052510b7fd420a15e6fcb185a613224d44cf021b25168c8e406879787171b347cf90f8addff90fb5ca842a2e6faf6707f869dfd6ad31882882f555f167558f38ce36b3fd0f58867723a6c6f5645a4f6e6951da8268e533b34b918c9ff5aeda231d98ea3266b3b9536afca58a3c1d8d4f05155323545646ff445ba0342c8a77e284bec31c6724879650ae886962a55d3918b9ef98f33c7a59187d2ddbe8c5cfb359bf06219e686038f85db4338042f763f7d79760f3a24ad0a16ee4e57792da98342089500089df7033c9b2be199cee0734601bfd9a19e026635ab3e99df7bda4f841d68c7e4ebe7950ec845cb519c",
			key:     []byte(base64.StdEncoding.EncodeToString(key)),
		}, want: content, wantErr: false},
		{name: "cfb de", args: args{
			content: "9afc1cb85bacb05f056de47282ca6668374bbd11ff6a32816ada1490a7d24c8d5d8f8fb4f07720105406499c44d3b3fbd5b5548b7e21fe6c220b3809662b1c691d59ea4589b7e3ebe284bc6d1435b933348cd78ee697c45483c949a863f86f86f981971d68f5c6dc8aaa598b7136cbf5783a434f233b0a645d2fb606a3c5264f31ff1694d10a7f9d1c6cb6ba733af45e53ed3822dbd4aaa1d99b1cc824f67625a9b1ae73374b3554700238c0b711917d18fbdfb120dd4c964519f6302ffce0109b1cc18f7d1698bbde7b44bf879713e81b788483ca4b7db22fd71f5db3933f13437768a24a82a096fad663667a4a0cb7be16a33b6526e8eb66339b",
			key:     []byte(hex.EncodeToString(key)),
		}, want: content, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CFBDecrypt(tt.args.content, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("CFBDecrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CFBDecrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}
