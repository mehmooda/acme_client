# acme_client

Requests certificates from an acme compliant endpoint (letsencrypt)

##Quickstart

1. Register Account Key (will create acme.ini in current working directory)
  - New Key:
    1. _openssl genrsa 4096 > account\_key.pem_
    1. _acme\_client register pem account\_key.pem_
  - Existing Key:
    1. _acme\_client register jwk private\_key.json_
1. edit acme.ini
1. _acme\_client_ (preferably as cron or systemd timer)


##Configuration

internal use denotes a variable which will be written and read by acme_client

|Variable Name|Valid Location|Description|
|---|---|---|
|ServerURL|ROOT|acme server address|
|ACCOUNT\_KEY|ROOT (internal use)|json encoding of rsa.PrivateKey use acme_client register|
|HTTP01|Domain|directory path where acme_client should place challenge files for authentication|
|SSLKEY|Domain|sslkey in pem format for csr generation|
|SSLECRT|Domain|sslcrt in pem format where acme_cient will place certificate|
|AUTH|Domain (internal use)|URL for auth object|
|CERTURL|Domain (internal use)|URL for existing certificate|

