package lazycrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

var magic = []byte("Salted__")

func newStream(salt []byte, passphrase []byte) (cipher.Stream, error) {
	hash := md5.New()
	data := make([]byte, 0, 32+aes.BlockSize)
	var sum []byte
	for {
		_, _ = hash.Write(sum)
		_, _ = hash.Write(passphrase)
		_, _ = hash.Write(salt)
		sum = hash.Sum(nil)
		hash.Reset()

		if len(data)+len(sum) >= cap(data) {
			data = append(data, sum[:cap(data)-len(data)]...)
			break
		}

		data = append(data, sum...)
	}

	key, iv := data[:32], data[32:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewCTR(block, iv), nil
}

func NewDecryptReader(passphrase []byte, r io.Reader) (io.Reader, error) {
	header := make([]byte, len(magic)+8)
	if _, tError := io.ReadFull(r, header); tError != nil {
		return nil, tError
	}

	if !bytes.HasPrefix(header, magic) {
		return nil, errors.New("invalid data")
	}

	salt := header[len(magic):]

	stream, err := newStream(salt, passphrase)
	if err != nil {
		return nil, err
	}

	return cipher.StreamReader{S: stream, R: r}, nil
}

func Decrypt(passphrase []byte, v []byte) ([]byte, error) {
	r, err := NewDecryptReader(passphrase, bytes.NewReader(v))
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(v)-len(magic)-8))
	if _, err := io.Copy(buf, r); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func DecryptString(passphrase []byte, s string) ([]byte, error) {
	v, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return Decrypt(passphrase, v)
}

func NewEncryptWriter(passphrase []byte, w io.Writer) (io.Writer, error) {
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	stream, err := newStream(salt, passphrase)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(magic)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(salt)
	if err != nil {
		return nil, err
	}

	return cipher.StreamWriter{S: stream, W: w}, nil
}

func Encrypt(passphrase []byte, v []byte) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, len(v)+len(magic)+8))

	w, err := NewEncryptWriter(passphrase, buf)
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(w, bytes.NewReader(v)); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func EncryptToString(passphrase []byte, v []byte) (string, error) {
	result, err := Encrypt(passphrase, v)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(result), nil
}
