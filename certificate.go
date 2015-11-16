package main

import "encoding/pem"
import "github.com/mehmooda/acme_client/acme"
import "os"
import "time"
import "bytes"
import "crypto/sha256"
import "encoding/hex"
import "io"
import "os/exec"

func GetCertificate(domain string, client *acme.Client) {
	certurl, ok := GLOBAL.HOST[domain]["CERTURL"]
	if ok {
		LogV("Downloading Existing Chain")
		chain, err := client.GetCertChain(certurl)
		if err != nil {
			LogE(err)
			return
		}
		LogV("Checking Certificate Validity")
		// Not Checking chain[0].Certificate.NotBefore
		// A lot of servers mess up their timezone information and have wrong time
		// Needs at least 30 days validity
		if time.Now().After(chain[0].Certificate.NotAfter.AddDate(0,0,-30)) {
			LogE("Certitfcate has less than 30 days validity")
		} else {
			LogV("Installing Chain")		
			InstallCertificates(domain,chain)
			return 		
		}
	}
	
	
	sslkey, ok := GLOBAL.HOST[domain]["SSLKEY"]
	if !ok {
		LogE("No SSLKEY given for", domain)
		return
	}
	key := Import_Rsa_Key_PEM(sslkey)
	if key == nil {
		LogE("Unable to load SSLKEY")
		return
	}
	_, ok = GLOBAL.HOST[domain]["SSLCERT"]
	if !ok {
		LogE("No SSLCERT given for", domain)
		return
	}

	LogV("Creating New Cert")
	cert, err := client.GetNewCert(key, domain)
	if err != nil {
		LogE(err)
	}
	GLOBAL.HOST[domain]["CERTURL"]=cert.Location
	UpdateConfig()
	LogV("Downloading New Cert Chain")

	chain, err := client.GetCertChain(cert.Location)
	if err != nil {
		LogE(err)
		return
	}
	LogV("Installing Chain")

	InstallCertificates(domain,chain)
}

func InstallCertificates(domain string,certs []*acme.Resource){
	buf := new(bytes.Buffer)	
	for _, cert := range certs {
		var a pem.Block 
		a.Type = "CERTIFICATE"
		a.Bytes = cert.Certificate.Raw
		err := pem.Encode(buf, &a)
		if err != nil {
			LogE(err)
			return
		}
	}
	
	CertificateFile := buf.Bytes()
	
	var oldSHA, newSHA []byte
	hasher := sha256.New()
	hasher.Write(CertificateFile)
	newSHA = hasher.Sum(nil)
	LogV("SHA256 of Certificate File", hex.EncodeToString(newSHA))
	
	
	file, err := os.Open(GLOBAL.HOST[domain]["SSLCERT"])
	if err == nil {
		hasher := sha256.New()
		io.Copy(hasher, file)
		oldSHA = hasher.Sum(nil)
		LogV("SHA256 of Existing Certificate File", hex.EncodeToString(oldSHA))
		file.Close()
		
		if bytes.Equal(oldSHA,newSHA) {
			LogV("Certificate already installed Not Installing")
			return
		}
		
	}
	
	file, err = os.Create(GLOBAL.HOST[domain]["SSLCERT"])
	if err != nil {
		LogE(err)
		return 
	}
	_, err = file.Write(CertificateFile)
	if err != nil {
		LogE(err)
	}
	file.Close()
	LogV("Reloading Server")
	
	reloadNginx()
}

func reloadNginx(){
	v := exec.Command("/usr/bin/sh","-c","sudo systemctl reload nginx")
	err := v.Run()
	if err != nil {
		LogE(err)
	}
}
