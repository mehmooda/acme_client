package acme

import "crypto/rsa"
import "encoding/json"
import "net/http"
import "bytes"
import "io"
import "net/url"

type ACME_URLS struct {
	Auth   string `json:"new-authz"`
	Cert   string `json:"new-cert"`
	Reg    string `json:"new-reg"`
	Revoke string `json:"revoke-cert"`
}

type Client struct {
	key          *rsa.PrivateKey
	urls         ACME_URLS
	replay_nonce string
}

type AcmeError struct {
	Type   string `json:"type,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func (e AcmeError) Error() string {
	return e.Type + " " + e.Detail
}

// CreateACMEServer returns a Client from an acme server directory uri
func CreateACMEClient(directoryuri string) (*Client, error) {
	c := new(Client)

	resp, err := http.Get(directoryuri)
	if err != nil {
		return nil, NewError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, NewErrorString("Directory URI returned Invalid Response Code")
	}
	//INIT
	c.replay_nonce = resp.Header["Replay-Nonce"][0]
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&c.urls)
	if err != nil {
		return nil, NewError(err)
	}

	return c, nil
}

func (c *Client) Nonce() (string, error) {
	return c.replay_nonce, nil
}

func (c *Client) Post(uri string, r *Resource) (*http.Response, error) {
	if c.key == nil {
		return nil, NewErrorString("ACCOUNT KEY NOT SET")
	}
	v, err := r.Sign(c)
	if err != nil {
		return nil, NewError(err)
	}

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(v))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, NewError(err)
	}
	c.replay_nonce = resp.Header["Replay-Nonce"][0]
	return resp, nil
}

func Get(uri string) (*http.Response, error) {
	return http.Get(uri)
}

func decode(r io.Reader, i interface{}) error {
	dec := json.NewDecoder(r)
	return dec.Decode(i)

}

func GetLocation(currenturl string, newurl string) string {
	u, _ := url.Parse(newurl)
	base, _ := url.Parse(currenturl)
	newu := base.ResolveReference(u)
	return newu.String()
}
