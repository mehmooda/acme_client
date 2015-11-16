package main

import "github.com/square/go-jose"
import "github.com/vaughan0/go-ini"
import "os"
import "crypto/rsa"
import "io/ioutil"
import "encoding/json"
import "encoding/pem"
import "crypto/x509"

type Config struct {
	HOST map[string]ini.Section
}

var GLOBAL Config

func Import_Rsa_Key_JWK(account_file string) *rsa.PrivateKey {
	file, err := os.Open(account_file)
	if err != nil {
		LogE("error:", err)
		return nil
	}
	defer file.Close()
	var letsencrypt_key jose.JsonWebKey
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&letsencrypt_key)
	if err != nil {
		LogE("error:", err)
		return nil
	}
	key := letsencrypt_key.Key.(*rsa.PrivateKey)
	return key
}

func Import_Rsa_Key_PEM(account_file string) *rsa.PrivateKey {
	file, err := os.Open(account_file)
	if err != nil {
		LogE("error:", err)
		return nil
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		LogE("error:", err)
		return nil
	}

	decoded, _ := pem.Decode(data)
	// TODO: HANDLE DECODING ERRORS

	key, err := x509.ParsePKCS1PrivateKey(decoded.Bytes)
	if err != nil {
		LogE("error:", err)
		return nil
	}
	return key
}

func GetAccountKeyJSON() []byte {
	v, err := json.Marshal(ACCOUNT_KEY)
	if err != nil {
		LogE(err)
		return nil
	}
	return v
}

func LoadConfiguration() bool {

	LogV("Opening ", *CONFIGURATION_FILE)
	file, err := ini.LoadFile(*CONFIGURATION_FILE)
	if err != nil {
		LogE(err)
		LogE("Use register to create a config file with account_key")
		return false
	}

	server, ok := file.Get("", "ServerURL")
	if !ok {
		LogE("Unable to find ServerURL")
		LogE("Use register to create a config file with account_key")
		return false
	}
	ACME_SERVER = &server

	name, ok := file.Get("", "ACCOUNT_KEY")
	if !ok {
		LogE("Unable to find account_key")
		LogE("Use register to create a config file with account_key")
		return false
	}

	err = json.Unmarshal([]byte(name), &ACCOUNT_KEY)
	if err != nil {
		LogE(err)
		return false
	}
	GLOBAL.HOST = file
	delete(GLOBAL.HOST, "")
	return true
}

func UpdateConfig() bool {
	file, err := os.Create(*CONFIGURATION_FILE)
	if err != nil {
		LogE(err)
		return false
	}
	defer file.Close()
	v := GetAccountKeyJSON()
	if v == nil {
		return false
	}
	file.Write([]byte("ServerURL="))
	file.Write([]byte(*ACME_SERVER))
	file.Write([]byte("\nACCOUNT_KEY="))
	file.Write(v)
	file.Write([]byte("\n"))
	for name, contents := range GLOBAL.HOST {
		file.Write([]byte("["))
		file.Write([]byte(name))
		file.Write([]byte("]\n"))
		for key, value := range contents {
			file.Write([]byte(key))
			file.Write([]byte("="))
			file.Write([]byte(value))
			file.Write([]byte("\n"))
		}
	}
	return true
}
