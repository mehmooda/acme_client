package acme

import "github.com/square/go-jose"
import "time"
import "encoding/base64"
import _ "crypto/sha256"
import "crypto"
import "fmt"

type Challenge struct {
	Type      string     `json:"type,omitempty"`
	Uri       string     `json:"uri,omitempty"`
	Status    string     `json:"status,omitempty"`
	Validated *time.Time `json:"validated,omitempty"`
	Error     *AcmeError `json:"error,omitempty"`
	//http-01, tls-sni-01, dns-01
	Token string `json:"token,omitempty"`
	//http-01, tls-sni-01, dns-01
	KeyAuthorization string `json:"keyAuthorization,omitempty"`
	//tls-sni-01
	TLSSNI_n int `json:"n,omitempty"`
	//dns-01

	//proofOfPossession-01
	//POPCerts []string `json:"certs"`
	//AccountKey

}

func (c *Client) ChallengeAccept(chal *Challenge) error {
	res := new(Resource)
	res.Resource = "challenge"
	res.Challenge = new(Challenge)
	res.Challenge.KeyAuthorization = chal.KeyAuthorization
	resp, err := c.Post(chal.Uri, res)
	if err != nil {
		return NewError(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
	if resp.StatusCode != 202 {
		var a AcmeError
		err = decode(resp.Body, &a)
		if err == nil {
			return NewError(a)
		}
		return NewErrorString(resp.Status)
	}
	return nil
}

func (c *Client) ChallengePoll(chal *Challenge) error {
	for {
		challenge, err := GetChallenge(chal.Uri)
		if err != nil {
			return NewError(err)
		}
		if challenge.Error != nil {
			return NewError(challenge.Error)
		}
		if challenge.Status == "pending" || challenge.Status == "processing" {
			<-time.After(1 * time.Second)
			continue
		}
		if challenge.Status == "valid" {
			return nil
		}
		return NewErrorString(challenge.Status)
	}
}

func GetChallenge(uri string) (*Challenge, error) {
	resp, err := Get(uri)
	if err != nil {
		return nil, NewError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 202 {
		chal := new(Challenge)
		err := decode(resp.Body, chal)
		if err != nil {
			return nil, NewError(err)
		}
		return chal, nil
	}
	var a AcmeError
	err = decode(resp.Body, &a)
	if err == nil {
		return nil, NewError(a)
	}
	return nil, NewErrorString(resp.Status)
}

func (c *Challenge) SetKeyAuth(client *Client) error {
	if c.KeyAuthorization != "" {
		return nil
	}

	jwk := jose.JsonWebKey{Key: client.key}
	t, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return NewError(err)
	}
	c.KeyAuthorization = c.Token + "." + base64.RawURLEncoding.EncodeToString(t)
	return nil
}

func (c *Challenge) HTTP01(client *Client) (string, string, error) {
	if c == nil {
		return "", "", NewErrorString("Not Challenge")
	}
	if c.Type != "http-01" {
		return "", "", NewErrorString("Not a HTTP01 Challenge")
	}

	err := c.SetKeyAuth(client)
	if err != nil {
		return "", "", NewError(err)
	}
	return c.Token, c.KeyAuthorization, nil

}
