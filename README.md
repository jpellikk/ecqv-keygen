# ecqv-keygen

Generate elliptic curve public/private key pair for certificate authority (CA):
```sh
$ openssl ecparam -name secp256k1 -genkey -noout -out ca_key.pem
$ openssl ec -in ca_key.pem -noout -text  ### print the key pair
```

Generate identity data:
```sh
$ echo -ne "id=42;username=jpellikk" > identity.txt
```

Run the ECQV key pair generator to create a new key pair and implicit certificate:
```sh
$ ./ecqv-keygen -i identity.txt -l ecqv.log ca_key.pem
```
