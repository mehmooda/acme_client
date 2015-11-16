package main

import "github.com/mehmooda/acme_client/acme"
import "os"

func PerformAuth(domain string, c *acme.Client, a *acme.Resource) bool {
	for n, combin := range a.Authorization.Combinations {
		completable := true
		for _, chal := range combin {
			if !CanCompleteChallenge(domain, a.Authorization.Challenges[chal].Type) {
				LogV("Combination",n,"Can not perform",a.Authorization.Challenges[chal].Type)
				completable = false
				break
			}
			LogV("Combination",n,"Can perform",a.Authorization.Challenges[chal].Type)
		}
		
		if completable {
			PerformCombination(domain, c, a, n)
			continue
		}
		
	}
	LogE("No combinations were completeable")
	return false
}

func CanCompleteChallenge(domain string, chaltype string) bool {
	switch(chaltype){
		case "http-01":
			_, ok := GLOBAL.HOST[domain]["HTTP01"]
			if ok {
				// Test if we can actually complete the challenge
				return true
			}
			return false
		default:
			return false
	}
}

func PerformCombination(domain string, client *acme.Client, auth *acme.Resource, n int) bool{
	for _, chaln := range auth.Authorization.Combinations[n] {
		challenge := &auth.Authorization.Challenges[chaln]
		switch(challenge.Type){
			case "http-01":
				filename, contents, err := challenge.HTTP01(client)
				if err != nil {
					LogE(err)
					return false
				}
				if !ChallengeHTTP01CreateFile(domain, filename,contents){
					return false
				}
				defer ChallengeHTTP01DeleteFile(domain, filename)
				
			default:
				return false
		}
		LogV("Asking for Verification")
		err := client.ChallengeAccept(challenge)
		if err != nil {
			LogE(err)
			return false
		}
		LogV("Polling for Verification")
		err = client.ChallengePoll(challenge)
		if err != nil {
			LogE(err)
			return false
		}
		LogV("Challenge Complete")
	}
	return true
}

func ChallengeHTTP01CreateFile(domain string, filename string, contents string) bool {
	base := GLOBAL.HOST[domain]["HTTP01"]
	file, err := os.Create(base + "/" + filename)
	if err != nil {
		LogE(err)
		return false
	}
	file.Write([]byte(contents))
	file.Close()
	return true
}

func ChallengeHTTP01DeleteFile(domain string, filename string){
	base := GLOBAL.HOST[domain]["HTTP01"]
	err := os.Remove(base + "/" + filename)
	if err != nil {
		LogE(err)
	}

}
