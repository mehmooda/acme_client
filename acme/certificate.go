package acme

import "crypto/rsa"
import "crypto/x509/pkix"
import "crypto/x509"
import "crypto/rand"
import "encoding/base64"
import "strconv"
import "time"
import "io/ioutil"
import "strings"

type CSR struct {
	Csr string `json:"csr,omitempty"`
}

func createCSR(key *rsa.PrivateKey, domain string) (string, error) {
	var subjectname pkix.Name
	subjectname.CommonName = domain
	var CSR x509.CertificateRequest
	CSR.Subject = subjectname
	csr, err := x509.CreateCertificateRequest(rand.Reader,&CSR,key)
	if err != nil {
		return "", NewError(err)
	}
	return base64.RawURLEncoding.EncodeToString(csr), nil
}

func (c *Client) GetNewCert(key *rsa.PrivateKey, domain string) (*Resource, error) {
	res := new(Resource)
	res.Resource = "new-cert"
	res.CSR = new(CSR)
	
	csr, err := createCSR(key, domain)
	if err != nil {
		return nil, NewError(err)
	}
	res.CSR.Csr = csr
	resp, err := c.Post(c.urls.Cert, res)
	if err != nil {
		return nil, NewError(err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 201 {
		cert, err := GetCert(GetLocation(c.urls.Cert,resp.Header["Location"][0]))
		if err != nil {
			return nil, NewError(err)
		}
		return cert, nil
	} else {
		var a AcmeError
		err = decode(resp.Body, &a)
		if err == nil {
			return nil, NewError(a)
		}
		return nil, NewErrorString(resp.Status)
	}
}


func GetCert(uri string) (*Resource, error){
	for {
		resp, err := Get(uri)
		if err != nil {
			return nil, NewError(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == 202 {
			tryafter, err :=strconv.Atoi(resp.Header.Get("Retry-After"))
			if err != nil {
				tryafter = 1
			}
			<-time.After(time.Duration(tryafter)*time.Second)
			continue
			
		}
		if resp.StatusCode == 200 {
			r := new(Resource)
			body, _ := ioutil.ReadAll(resp.Body)
			r.Certificate, err = x509.ParseCertificate(body)
			if err != nil {
				return nil, NewError(err)
			}
			r.Location = uri
			r.Links = resp.Header["Link"]
			return r, nil
		}
		var a AcmeError
		err = decode(resp.Body, &a)
		if err == nil {
			return nil, NewError(a)
		}
		return nil, NewErrorString(resp.Status)
	}
}

func (r *Resource) CertificateGetIssuer() string {
	for _, header := range r.Links {
		v := strings.Split(header,";")
		if(v[1]=="rel=\"up\""){
			agr := v[0][1:len(v[0])-1]
			return GetLocation(r.Location, agr)
		}
	}
	
	return ""
}

func (c *Client) GetCertChain(certurl string) ([]*Resource, error){
	var certs []*Resource
	
	for {
		cert, err := GetCert(certurl)
		if err != nil {
			return nil, NewError(err)
		}
		certs = append(certs, cert)
		certurl = cert.CertificateGetIssuer()
		if certurl == "" {
			return certs, nil
		}
	}
}