package acme

import "time"
import "strings"

type Authorization struct {
	Identifier   *Identifier `json:"identifier,omitempty"`
	Status       string      `json:"status,omitempty"`
	Expires      *time.Time  `json:"expires,omitempty"`
	Challenges   []Challenge `json:"challenges,omitempty"`
	Combinations [][]int     `json:"combinations,omitempty"`
}

type Identifier struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

func (c *Client) NewAuthorization(domain string) (*Resource, error) {
	r := new(Resource)
	r.Resource = "new-authz"
	r.Authorization = new(Authorization)
	r.Authorization.Identifier = new(Identifier)
	r.Authorization.Identifier.Type = "dns"
	r.Authorization.Identifier.Value = domain

	resp, err := c.Post(c.urls.Auth, r)
	if err != nil {
		return nil, NewError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 403 {
		var a AcmeError
		err := decode(resp.Body, &a)
		if err == nil {
			return nil, NewError(a)
		}
		return nil, NewErrorString("Unhandled Response from NewAuthorization")
	} else if resp.StatusCode == 201 {
		res := new(Resource)
		res.Location = GetLocation(c.urls.Auth, resp.Header["Location"][0])
		err := decode(resp.Body, &res.Authorization)
		if err != nil {
			return nil, NewError(err)
		}
		return res, nil
	} else {
		return nil, NewErrorString(resp.Status)
	}
}

func GetAuthorization(uri string) (*Resource, error) {
	resp, err := Get(uri)
	if err != nil {
		return nil, NewError(err)
	}

	if resp.StatusCode == 200 {
		res := new(Resource)
		err := decode(resp.Body, &res.Authorization)
		if err != nil {
			return nil, NewError(err)
		}
		res.Location = uri
		return res, nil
	}

	var a AcmeError
	err = decode(resp.Body, &a)
	if err == nil {
		return nil, NewError(a)
	}
	return nil, NewErrorString("Unhandled Response from NewAuthorization")
}

func (a *Authorization) MatchesIdent(domain string) bool {
	if a != nil {
		if a.Identifier != nil {
			return strings.EqualFold(a.Identifier.Value, domain)
		}
	}
	return false
}

func (a *Authorization) AuthMatchesIdent(domain string) bool {
	if a != nil {
		if a.Identifier != nil {
			return strings.EqualFold(a.Identifier.Value, domain)
		}
	}
	return false
}

func (a *Authorization) AuthNeedsCompletion() bool {
	if a != nil {
		switch a.Status {
		case "pending":
			return true
		case "":
			return true
		default:
			return false
		}
	}
	return false
}

func (a *Authorization) AuthValid() bool {
	if a != nil {
		// Check Expiry?
		return a.Status == "valid"
	}
	return false
}
