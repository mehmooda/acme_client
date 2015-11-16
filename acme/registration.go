package acme

import "crypto/rsa"
import "strings"

type Registration struct {
//	Key string `json:"key,omitempty"`
	Contact []string `json:"contact,omitempty"`
	Agreement string `json:"agreement,omitempty"`
	Authorizations []string `json:"authorizations,omitempty"`
	Certificates string `json:"certificates,omitempty"`
}


func (c *Client) SetAccountKey(key *rsa.PrivateKey) {
	c.key = key
}

	
func (c *Client) GetRegistration() (*Resource, error) {

	res := new(Resource)
	postresource := new(Resource)
	postresource.Resource = "new-reg"
	
	resp, err := c.Post(c.urls.Reg,postresource)
	if err != nil {
		return nil, NewError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 201 {
		res.Location = resp.Header["Location"][0]
		res.Links = resp.Header["Link"]
		err = decode(resp.Body, &res.Registration)
		if err != nil {
			return nil, NewError(err)
		}
		return res, nil
	} else if resp.StatusCode == 409 {
		res.Location = resp.Header["Location"][0]
		postresource.Resource = "reg"
		resp, err = c.Post(res.Location, postresource)
		if err != nil {
			return nil, NewError(err)
		}
		defer resp.Body.Close()
		res.Links = resp.Header["Link"]
		err = decode(resp.Body, &res.Registration)
		if err != nil {
			return nil, NewError(err)
		}
		return res, nil
	} else {
		//Attempt to download error
		var a AcmeError
		err := decode(resp.Body, &a)
		if err == nil {
			return nil, NewError(a)
		}
		return nil, NewErrorString("Unhandled Response from Registration")
	}
}

func (c *Client) AgreeToTerms(r *Resource, terms string) error {
	ar := new(Resource)
	ar.Resource="reg"
	ar.Registration = new(Registration)
	ar.Agreement = terms
	resp, err := c.Post(r.Location,ar)
	if err != nil {
		return NewError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 202 {
		r.Links = resp.Header["Link"]
		err = decode(resp.Body, &r.Registration)
		return nil
	}
	var a AcmeError
	err = decode(resp.Body,&a)
		if err != nil {
		return NewError(a)
	}
	return NewErrorString(resp.Status)
}

func (r *Resource) NeedsAgreement() string {
	for _, header := range r.Links {
		v := strings.Split(header,";")
		if(v[1]=="rel=\"terms-of-service\""){
			agr := v[0][1:len(v[0])-1]
			if r.Agreement != agr {
				return agr
			} else {
				return ""
			}
		}
	}
	
	return ""
}
