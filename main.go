package main

import "github.com/mehmooda/acme_client/acme"
import "flag"

//import "encoding/json"
//import "encoding/pem"

import "crypto/rsa"

var CONFIGURATION_FILE *string
var ACME_SERVER *string
var LOGLEVEL *int
var ACCOUNT_KEY *rsa.PrivateKey

func main() {
	//	flag.Usage = Usage
	CONFIGURATION_FILE = flag.String("c", "acme.ini", "load data file")
	ACME_SERVER = flag.String("s", "https://acme-staging.api.letsencrypt.org/directory", "ACME SERVER DIRECTORY")
	LOGLEVEL = flag.Int("v", 3, "LOGLEVEL 0:SILENT, 1:ERRORS, 2:VERBOSE, 3:NETWORK")
	flag.Parse()

	n := flag.NArg()
	if n > 2 {
		if flag.Arg(0) == "register" {
			LogV("Creating Acme Client from",
				*ACME_SERVER)
			client, err := acme.CreateACMEClient(*ACME_SERVER)
			if err != nil {
				LogE(err)
			}
			switch flag.Arg(1) {
			case "pem":
				LogV("Parsing", flag.Arg(2), "with pem")
				ACCOUNT_KEY = Import_Rsa_Key_PEM(flag.Arg(2))
			case "jwk":
				LogV("Parsing", flag.Arg(2), "with jwk")
				ACCOUNT_KEY = Import_Rsa_Key_JWK(flag.Arg(2))
			default:
				LogE("Unsupported Key format:", flag.Arg(1))
				return
			}
			if ACCOUNT_KEY == nil {
				return
			}
			client.SetAccountKey(ACCOUNT_KEY)
			LogV("Attempting to retrieve Registration")
			registration, err := client.GetRegistration()
			if err != nil {
				LogE(err)
				return
			}
			s := registration.NeedsAgreement()
			if s != "" {
				LogV("Agreeing to Terms:", s)
				err = client.AgreeToTerms(registration, s)
				if err != nil {
					LogE(err)
					return
				}
			}
			LogN(registration)
			UpdateConfig()
			return
		}
	}

	if !LoadConfiguration() {
		return
	}

	client, err := acme.CreateACMEClient(*ACME_SERVER)
	LogV("Getting Registration")
	client.SetAccountKey(ACCOUNT_KEY)
	_, err = client.GetRegistration()
	if err != nil {
		LogE(err)
		return
	}
	// TODO: Use Registration object to get auth_urls if server implements
	LogV("Find Authorizations")
	for name, _ := range GLOBAL.HOST {
		LogV("Getting Auth:", name)
		a := GetAuth(name, client)
		if a == nil {
			continue
		}
		if a.AuthNeedsCompletion() {
			if !PerformAuth(name, client, a) {
				LogE("Unable to Authorize:", name)
			}
			//Update Authorization Object
			a = GetAuth(name, client)
		}

		if a.AuthValid() {
			GetCertificate(name, client)
		}
	}

}

func GetAuth(name string, client *acme.Client) *acme.Resource {
	url, ok := GLOBAL.HOST[name]["AUTH"]
	var auth *acme.Resource
	var err error
	if ok {
		auth, err = acme.GetAuthorization(url)
		if err != nil {
			LogE(err)
		}
	}
	if auth == nil || !auth.AuthMatchesIdent(name) || !auth.AuthValid() {
		auth, err = client.NewAuthorization(name)
		if err != nil {
			LogE(err)
			return nil
		}

	}
	GLOBAL.HOST[name]["AUTH"] = auth.Location
	UpdateConfig()
	return auth
}
