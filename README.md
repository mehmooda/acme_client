# acme_client

3 Step usage:

1. copy acme.ini into your working directory
2. edit acme.ini
3. openssl genrsa 4096 > account_key.pem
4. acme_client register pem account_key
5. acme_client ... preferably in cron once a week


Note: This will run "sudo systemctl reload nginx"

Configuration Options:

ServerURL = ACME Server directory Url

HTTP01 = acme-challenge directory
SSLKEY = ssl key to be read 
SSLCERT = ssl certificate to be outputted
