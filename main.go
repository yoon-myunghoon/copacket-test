package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
)

func GenKeys() error {

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privFile, err := os.Create("private_key.pem")
	if err != nil {
		return err
	}

	pemData := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}

	err = pem.Encode(privFile, pemData)
	if err != nil {
		return err
	}

	privFile.Close()

	fmt.Println("Your keys have been written to private_key.pem")

	return nil

}

func GetKeys() (*rsa.PrivateKey, error) {

	file, err := os.Open("private_key.pem")
	if err != nil {
		return nil, err
	}

	defer file.Close()

	//Create a byte slice (pemBytes) the size of the file size
	pemFileInfo, _ := file.Stat()
	var size = pemFileInfo.Size()
	pemBytes := make([]byte, size)

	//Create new reader for the file and read into pemBytes
	buffer := bufio.NewReader(file)
	_, err = buffer.Read(pemBytes)
	if err != nil {
		return nil, err
	}

	//Now decode the byte slice
	data, _ := pem.Decode(pemBytes)
	if data == nil {
		return nil, errors.New("could not read pem file")
	}

	privKeyImport, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		return nil, err
	}

	return privKeyImport, nil

}

func Encrypt(pub *rsa.PublicKey, text string) ([]byte, error) {

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pub,
		[]byte(text),
		nil)
	if err != nil {
		return nil, err
	}

	return encryptedBytes, nil
}

func Decrypt(privKey *rsa.PrivateKey, cipherText []byte) ([]byte, error) {

	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), nil, privKey, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return decryptedBytes, nil
}

func main() {

	var action = flag.String("action", "decrypt", "Whether to decrypt or encrypt")
	flag.Parse()
	task := *action

	var err error

	if task == "gen" {
		//gen the priv key and write to file
		err = GenKeys()
		if err != nil {
			fmt.Println("Could not generate keys:", err)
		}
	}

	if task == "encrypt" {

		//Get key from file
		privateKey, err := GetKeys()
		if err != nil {
			fmt.Println("Could not retrieve key file", err)
			return
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Println("Please enter the text you would like to encrypt: ")
		text, _ := reader.ReadString('\n')

		cipherText, err := Encrypt(&privateKey.PublicKey, text)
		if err != nil {
			fmt.Println("Could not encrypt", err)
			return
		}

		fmt.Printf("Encrypted message: %x", cipherText)
	}

	if task == "decrypt" {

		//Get key from file
		// privateKey, err := GetKeys()
		// if err != nil {
		// 	fmt.Println("Could not retrieve key file", err)
		// }
		// fmt.Println(privateKey)

		privateKeyFile, err := os.Open("/Users/logstack2/key_test/server-key.pem")
		// privateKeyFile, err := os.Open("private_key.pem")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		pemfileinfo, _ := privateKeyFile.Stat()
		var size int64 = pemfileinfo.Size()
		pembytes := make([]byte, size)
		buffer := bufio.NewReader(privateKeyFile)
		_, err = buffer.Read(pembytes)
		data, _ := pem.Decode([]byte(pembytes))
		privateKeyFile.Close()

		privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		// fmt.Println("Private Key : ", privateKeyImported)

		var text string
		fmt.Println("Please enter the cypher text you would like to decrypt: ")
		fmt.Scan(&text)
		textHexDec, _ := hex.DecodeString(text)

		fmt.Println("textHexDec text: ", textHexDec)

		// sha256 적용하기
		hash := sha256.New()
		hash.Write(textHexDec)
		md := hash.Sum(nil)
		mdStr := hex.EncodeToString(md)

		fmt.Println("mdStr text: ", mdStr)

		decryptedText, err := Decrypt(privateKeyImported, textHexDec)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("Decrypted text: ", string(decryptedText))
	}

}
