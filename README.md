# opa-sginature-poc
POC of the new OPA .signature file for OPA bundles.

This repository contains:
1. Sample policy and data files under the directory `/db`. `/db/uam2` is the one used in the sample codes for testing
2. `/java` directory contains the Java implementation pf signing bundles using [NIMBUS JOSE + JWT](https://bitbucket.org/connect2id/nimbus-jose-jwt/wiki/Home) library. This library supports both compact and non-compact serialisation of JWS objects. It is also using [PICOCLI](https://picocli.info/) library for CLI implementation
3. `/go` directory contains the GO implementation of signing bundles using [GO-JOSE](https://github.com/square/go-jose) library. Currently this library support only compact serialisation of JWS objects. It is also using [Cobra](https://github.com/spf13/cobra) library for CLI implementation
4. `/data` directory contains the a subdirectory `/uam2` which contains the files to be signed and a JSON file `payload.json` which contains the list of files under `uam2` directory and their SHA hash. Command can use either target directory `uam2` or the payload JSON file directory to pass in the input to be signed
5. `rsa` directory contains a test primary key (`primaryKey.pem`) and a public key (`publicKey.pub`) to be used to generate a signature and/or verify the signature
6. Running either `GO` or `Java` utility produces 2 signature files under the root (`.`) directory:
       1. `sig-RSA.json`: This file contains the signature/JWT token generated using asymmetric RSA keys and using compact serialisation of JWS object
       2. `sig-HMAC.json`: This file contains the signature/JWT token generated using symmetric keys (using secret key) i.e. HMAC algo and using compact serialisation of JWS object


## Runing the POC

Each command should produce `Exit Codes` as follows:
- `0` - Successful execution
- `1` - Error occurred
- `2` - Usage message (only for Go)

Check the command usage for both, Go and Java, using below commands:
```bash
<./go-opasign | ./java-opasign.sh> --help
```

```bash
<./go-opasign | ./java-opasign.sh> <create | list | verify> --help
```

### Follow below steps to run Go code
- Switch to the `go` directory for Go project
- Build the Go Project. This will produce an executable binary in the parent/root directory
```bash
go build -o ../go-opasign main.go
```
- Switch back to the root directory (`opa-signature-poc`). Now you can play around with commands from here for both Java and Go implementations
- Check out the `java-opasign help` or `java-opasign help <subcommand>` (where `subcommand` is either `create` or `verify`) command to see various options and arguments available to use
- Create a signature by either passing a target directory or by passing the payload itself using below command. This will generate `sig-rsa.json` file in the root directory
```bash
./go-opasign create sig-rsa.json -k rsa/privateKey.pem -p data/payload.json
```
or 
```bash
./go-opasign create sig-rsa.json -k rsa/privateKey.pem -t data/uam2/
```
- List down the generated signature from the signature file using below command
```bash
./go-opasign list sig-rsa.json
```
- Verify the signature in the `sig-rsa.json` file using below command
```bash
./go-opasign verify sig-rsa.json -k rsa/publicKey.pub -t data/uam2/
```
- By default, it uses asymmetric RSA keys (RS256 algorithm). If you want to test it for symmetric keys (i.e. using HMAC algorithm). Below command can be used to create and verify the signatures
```bash
./go-opasign create sig-hmac.json -a HMAC -k "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ" -p data/payload.json
```
```bash
./go-opasign list sig-hmac.json
```
```bash
./go-opasign verify sig-hmac.json -a HMAC -k "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ" -t data/uam2/
```


### Follow below steps to run Java code
- Switch to the `java` directory for Java project
- Build the Java project
```bash
./gradlew build
```
- Define the alias for the root command and append it in your bash profile (e.g. `.bash_profile`). Provide the absolute path if you want to run the command from any directory. Then restart your shell (or do `source ~/.bash_profile` if you don't want to restart it) 
```bash
alias java-opasign="java -jar java/build/libs/opa-signature-poc-1.0-SNAPSHOT.jar"
```
Or use the `java-opasign.sh` script to execute the commands as shown in the commands below.

- Switch back to the root directory (`opa-signature-poc`). Now you can play around with commands from here for both Java and Go implementations
- Check out the `java-opasign help` or `java-opasign help <subcommand>` (where `subcommand` is either `create` or `verify`) command to see various options and arguments available to use
- Create a signature by either passing a target directory or by passing the payload itself using below command. This will generate `sig-rsa.json` file in the root directory
```bash
./java-opasign.sh create sig-rsa.json -k rsa/privateKey.pem -p data/payload.json
```
or 
```bash
./java-opasign.sh create sig-rsa.json -k rsa/privateKey.pem -t data/uam2/
```
- List down the generated signature from the signature file using below command
```bash
./java-opasign.sh list sig-rsa.json
```
- Verify the signature in the `sig-rsa.json` file using below command
```bash
./java-opasign.sh verify sig-rsa.json -k rsa/publicKey.pub -t data/uam2/
```
- By default, it uses asymmetric RSA keys (RS256 algorithm). If you want to test it for symmetric keys (i.e. using HMAC algorithm). Below command can be used to create and verify the signatures
```bash
./java-opasign.sh create sig-hmac.json -a HMAC -k "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ" -p data/payload.json
```
```bash
./java-opasign.sh list sig-hmac.json
```
```bash
./java-opasign.sh verify sig-hmac.json -a HMAC -k "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ" -t data/uam2/
```