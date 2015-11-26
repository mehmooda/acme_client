package acme

import "github.com/square/go-jose"
import "encoding/json"
import "crypto/x509"

type Resource struct {
	Resource string `json:"resource,omitempty`
	*Registration
	*Authorization
	*Challenge
	*CSR
	Location    string            `json:"-"`
	Links       []string          `json:"-"`
	Certificate *x509.Certificate `json:"-"`
}

func (r *Resource) Sign(c *Client) ([]byte, error) {
	s, err := jose.NewSigner(jose.PS512, c.key)
	if err != nil {
		return nil, NewError(err)
	}

	resourcejson, err := json.Marshal(r)
	if err != nil {
		return nil, NewError(err)
	}
	s.SetNonceSource(c)
	jws, err := s.Sign(resourcejson)
	if err != nil {
		return nil, NewError(err)
	}
	v := jws.FullSerialize()
	return []byte(v), nil
}
