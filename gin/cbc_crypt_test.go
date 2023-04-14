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
	cipherKey  = "VEVTVCBKT1NFIENZUEhFUg=="
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
			key:     key,
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
			content: "ad7c3b466a6eea1e4164ccd22bbf39fd81861797df77ca844cfe337e1919ccadc81c727a1680a095bf787f9685575039b184f6e674d1a288f27928550350506a558583a9721840924d0f43c3f8e7f78ce4b5e9584d09f04840d67ed4ba5f6824b6c10a667e744fce136914d72294f659a060cdaf9d1a2a5153c317bfb4b8fa9080c58fa56c6a55c02b3d67b1ebe1c1dbcfab815f0599227d62659b868b8813029c3b82cb17862fa700ebb0f0eab19e575a316d300a25137a074722a0d357b648e1acc2d732fc87bddb9bfaa0833f7b3f174013fe1ad1927a33af9f95f009b39a6c724d71ce4f3b6bcd6e01c5cb1dbe2f380a596cc7428e8b8cba31",
			key:     key,
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
			t.Log(got)
			fmt.Println(hex.EncodeToString([]byte("ad7c3b466a6eea1e4164ccd22bbf39fd81861797df77ca844cfe337e1919ccadc81c727a1680a095bf787f9685575039b184f6e674d1a288f27928550350506a558583a9721840924d0f43c3f8e7f78ce4b5e9584d09f04840d67ed4ba5f6824b6c10a667e744fce136914d72294f659a060cdaf9d1a2a5153c317bfb4b8fa9080c58fa56c6a55c02b3d67b1ebe1c1dbcfab815f0599227d62659b868b8813029c3b82cb17862fa700ebb0f0eab19e575a316d300a25137a074722a0d357b648e1acc2d732fc87bddb9bfaa0833f7b3f174013fe1ad1927a33af9f95f009b39a6c724d71ce4f3b6bcd6e01c5cb1dbe2f380a596cc7428e8b8cba31")))
		})
	}
}
