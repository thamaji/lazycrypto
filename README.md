lazycrypto
====

雑に暗号化したいとき使うやつ。

きっと `openssl aes-256-ctr` 互換の暗号化、復号化をする。

## Example

```
package main

import (
	"fmt"
	"log"

	"github.com/thamaji/lazycrypto"
)

func main() {
	passphrase := []byte("hoge")
	secureText, err := lazycrypto.EncryptToString(passphrase, []byte("fuga"))
	if err != nil {
		log.Fatalln(err)
	}

	plainText, err := lazycrypto.DecryptString(passphrase, secureText)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(string(plainText))
}
```
