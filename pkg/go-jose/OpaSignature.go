package main

import (
	//"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// File denotes the type that holds the file path and their SHA hash
type File struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha-256"`
}

func fromHexInt(base16 string) *big.Int {
	re := regexp.MustCompile(`\s+`)
	val, ok := new(big.Int).SetString(re.ReplaceAllString(base16, ""), 16)
	if !ok {
		panic("Invalid test data")
	}
	return val
}

func main() {
	// Generate a random RSA key pair every time
	//privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	//if err != nil {
	//	fmt.Println("Error in main()")
	//	return
	//}

	// Generate PrivateKey by providing Modulus and Exponent
	// From - https://blog.ndpar.com/2017/04/11/rsa-private-key/
	//privateKey := &rsa.PrivateKey{
	//	PublicKey: rsa.PublicKey{
	//		N: fromHexInt(`01D58729C5FFE1785360D7A2B532EAA6329C9B8BD95AF105422B40368630F636E1CB0B847D74798BD95249B42A47971BB5903FC87A97B7D541AC599961B8B0EB6CF24F7DFC798434EAE2E3D4E741D4FEC9C696208015205A50258B688A5475751B361C57CAEBE26DB3CF92AA4F4A69DD936E14A7A58072CFF461035ED9D448D1161E2C0DFFDF2A36B42CABC6B2D8FDACB7BC4C113890E69124E4FBD488AF9FBC5550C7586C5412E01A6DE9F2A8966E7C183C5A4CADD93E85FE6B1286211DEE62F29274358F569E20F169F1A2D01259710503AC6AD1DA8FC2C6C4C6933C78D1AE37DE30A0A84676FD11D95D43B5B93C032F52CEC2B1E636FC94E9FEA2F321A668FF`),
	//		E: 65537,
	//	},
	//	D: fromHexInt(`2D426781C68B4810AC227274B50119742CD471994A1836EC37446BFD1375D30F2B860E0769D582E837F3BD8235D46DBF5AB5A09AF09FAFD6DCC8E642C7E2DB4EC282172037367498BA60EBD7943E4BDBCCB611514762B9A74577380F32DA54FCD7D7C8E9594397AA358AC0655444502F889F9A696C5AFA3611AE997E0B3B2F0185C60257E90D1955546F0190DF57F1674F0AD912BD8FFEAEAE65A79E0D9783E980E3C5CCC1B18D524296B806BDA4EC28DF028CCDA91FD94A89228EFA1B82A6B0B4C0A142EE7C890BE97C30F58232BEC26E897E25FC61B432CC651F82622132F3BE34E764623E4DD75DD469703C0081DCCE7F58C8A3DC72D46FB2BE548E5AF641`),
	//	Primes: []*big.Int{
	//		fromHexInt(`010CA88D97C90A5544D1CA63A5916B20CA2FC92C5CE2EB43409D953009630B322723D15581610A6CFE7686710A0086776C8929106646A4118CDC937E1B443F32D8B8255F4AB631D11C818D4D3411CF72D41780FC6354E6198BD6BE6D9790C12F6CB596B1C9BAC4F53B34C833375B60E1EC5EF71407FBA5229BDECEE38C8841432B`),
	//		fromHexInt(`01BF67B98C4202D2BF8510B0F84752C26BF6C1E3C464B6678E612904F471A2D9E3A251B39416701F19290EC9957EA1EBB08ADABD3088018E7F81A57F3E287C3387EFDDC6ABBA7CDD446F089930071EDD3D06EB0D69AA334F23C7C7E8648AFC4C3C781BEBE6428949A2841E555B754685C2AAF2BA1E6F7F1A049CABFDC7FD5F577D`),
	//	},
	//	Precomputed: struct {
	//		Dp, Dq    *big.Int
	//		Qinv      *big.Int
	//		CRTValues []rsa.CRTValue
	//	}{
	//		Dp:        fromHexInt(`685B5CCCD5F1E69759EA84F47E5D1F9A8A1F59D526EBFDEEAE8791E6438BC8CA7D56462180815D3F26E928259B78A0110FE25C956DE13354052661B8D3B4BCDA84053853BC1BF3BF5FEF744AC2945365614FE039F17383FED6C697A965383564C3D0AA74D2D0C8F55B965C96A72F25F2FC1C7BB272247E220FD54B7C7E3CE38B`),
	//		Dq:        fromHexInt(`4572D7658335A6FB1DAFAA98CF91742688262EB1E4A43FCCE51E15EBCFDBE490A638A274814B2438A69BEA04AFA478CE6DAF68A0A8EBFCEFA3F3499E1F70B01B10CBCF3406FDACE71B892D263C64B918E9030190FE5F7A9066498CB456B2B52EC9C223CB1956F03C2EDFFA85F8DD5A940E2F215EEA15C3B7258EB9151B2A7A8D`),
	//		Qinv:      fromHexInt(`89A217111B58DD54CCFB00C4873DB4EF6716283AEA77D2B46D85F1D8D47F2C0EC21AA37EBB26781C19EC43EB9583FB47205D83692D7CDCA9528B69C19EEFC100624A31907B33AFB9008C4685EB8AB709B890D7C6A6BD50BD41EE5A373FD31701F516FDB30C694243FBCB0851E237EA31703A2BC2A945EE5B9F12DCD574F3FBCB`),
	//		CRTValues: []rsa.CRTValue{},
	//	},
	//}

	// Generate/Read PrivateKey from the file
	pkByte, err := ioutil.ReadFile("db/privateKey.pem")
	if err != nil {
		log.Fatal(err)
	}
	privateKey := mustUnmarshalRSA(pkByte)

	// Define a symmmetric sercret key for HMAC algo
	secretForHMAC := "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"

	//fmt.Println("\nSecret/Symmetric Key: " + secret)
	fmt.Println("============================ Verify existing tokens of signature files ========================")
	//verifyJWSWithRSA(privateKey.PublicKey, "db/uam2/signature-full.json", false)
	verifyJWSWithRSA(privateKey.PublicKey, "db/uam2/.signature-compact-RSA", true)
	verifyJWSWithHMAC(secretForHMAC, "db/uam2/.signature-compact-HMAC", true)

	fmt.Println("\n============================ Generate new tokens using GO implementation ========================")
	files := scanDir("db/uam2")
	fmt.Printf("Files JSON Payload: \n%s\n", files)

	fmt.Println("\n============================ Using FULL JSON Serialisation========================")
	jwsJSON := createJWSWithRSA(privateKey, files, false)
	fmt.Printf("JWS Token Serialised: \n%s\n", jwsJSON)
	verifyJWSWithRSA(privateKey.PublicKey, "db/uam2/.signature-full-RSA", false)

	fmt.Println("\n============================ Using COMPACT Serialisation==========================")
	jwsJSONC := createJWSWithRSA(privateKey, files, true)
	fmt.Printf("JWS Token Serialised: \n%s\n", jwsJSONC)
	verifyJWSWithRSA(privateKey.PublicKey, "db/uam2/.signature-compact-RSA", true)

	fmt.Printf("\n============================ Using Secret/Symmetric Key==========================\n")
	jwsJSONHMAC := createJWSWithHMAC(secretForHMAC, files, true)
	fmt.Printf("JWS Token Serialised: \n%s\n", jwsJSONHMAC)
	verifyJWSWithHMAC(secretForHMAC, "db/uam2/.signature-compact-HMAC", true)
}

// createJWSWithRSA
func createJWSWithRSA(privateKey *rsa.PrivateKey, files []File, isCompact bool) string {
	// Instantiate a signer using RSASSA-PSS (SHA512) with the given private key.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, &jose.SignerOptions{
		//NonceSource:  nil,
		//EmbedJWK:     false,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": "uam2-opa-poc",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Public JWT Claims
	cl := jwt.Claims{
		//Subject: "subject",
		Issuer: "JWTService",
		//NotBefore: jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
		//Expiry:    jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 15, 0, 0, time.UTC)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
		//Audience: jwt.Audience{"leela", "fry"},
	}

	filesBuf, err := json.Marshal(files)
	if err != nil {
		log.Fatal(err)
	}

	clBytes := jwt.Signed(signer).
		Claims(&cl).
		Claims(map[string]interface{}{
			"files": string(filesBuf),
		}).
		Claims(map[string]interface{}{
			"scope": "AU.GLOBAL.OPA.WRITE",
		}).
		Claims(map[string]interface{}{
			"jwks-url": "https://github.com/csp/opa-sourcedata-bundles",
		})

	//filesBuf, err := json.Marshal(files)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//jwsObject, err := signer.Sign(filesBuf)
	//if err != nil {
	//	log.Fatal(err)
	//}

	var jwsJSON string
	if isCompact {
		jwsJSON, _ = clBytes.CompactSerialize()
		//Write to file signature-compact.json
		err = ioutil.WriteFile("db/uam2/.signature-compact-RSA", []byte(jwsJSON), 0600)
		if err != nil {
			log.Fatal(err)
		}
		return jwsJSON
	}

	jwsJSON, _ = clBytes.FullSerialize()
	//Write to file signature-compact.json
	err = ioutil.WriteFile("db/uam2/.signature-full-RSA", []byte(jwsJSON), 0600)
	if err != nil {
		log.Fatal(err)
	}
	return jwsJSON
}

// verifyJWSWithRSA
func verifyJWSWithRSA(publicKey rsa.PublicKey, filePath string, isCompact bool) []File {
	// Check if file exists or not
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		log.Println(err)
		return []File{}
	}
	// Read the file content
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}
	if len(bytes) == 0 {
		fmt.Printf("No content found in the file ->%v\n", filePath)
		return []File{}
	}
	fmt.Printf("\nToken found in "+filePath+" ->\n%s\n", string(bytes))

	jwsObject, err := jwt.ParseSigned(string(bytes))
	if err != nil {
		log.Fatal(err)
	}

	output := make(map[string]interface{})
	err = jwsObject.Claims(&publicKey, &output)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("JWT Claims (verified):\n%s\n", output)

	//output, err := jwsObject.Verify(&publicKey)
	//if err != nil {
	//	log.Fatal(err)
	//}

	fStr := output["files"]
	var files []File
	err = json.Unmarshal([]byte(fStr.(string)), &files)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("JWT Bundles Payload (verified):\n%s\n", files)

	for _, f := range files {
		hasher := sha256.New()
		fd, err := os.Open(f.Name)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := io.Copy(hasher, fd); err != nil {
			log.Fatal(err)
		}
		fd.Close()
		if f.Sha256 != hex.EncodeToString(hasher.Sum(nil)) {
			log.Fatalf("File %s has different sha256\nExpected=%s\nGot=%s\n", f.Name, f.Sha256, hex.EncodeToString(hasher.Sum(nil)))
		}
		//fmt.Println(f)
		//fmt.Println("File Out ->", f)
	}
	return files
}

// createJWSWithRSA
func createJWSWithHMAC(secret string, files []File, isCompact bool) string {
	// Instantiate a signer using HMAC using SHA-256 with the given private key.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(secret)}, nil)
	if err != nil {
		log.Fatal("1 -----", err)
	}

	// Public JWT Claims
	cl := jwt.Claims{
		//Subject: "subject",
		Issuer: "JWTService",
		//NotBefore: jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
		//Expiry:    jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 15, 0, 0, time.UTC)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
		//Audience: jwt.Audience{"leela", "fry"},
	}

	filesBuf, err := json.Marshal(files)
	if err != nil {
		log.Fatal(err)
	}
	clBytes := jwt.Signed(signer).
		Claims(&cl).
		Claims(map[string]interface{}{
			"files": string(filesBuf),
		}).
		Claims(map[string]interface{}{
			"scope": "AU.GLOBAL.OPA.WRITE",
		}).
		Claims(map[string]interface{}{
			"jwks-url": "https://github.com/csp/opa-sourcedata-bundles",
		})

	//jwsObject, err := signer.Sign(filesBuf)
	//if err != nil {
	//	log.Fatal("2 -----", err)
	//}

	var jwsJSON string
	if isCompact {
		jwsJSON, _ = clBytes.CompactSerialize()
		//Write to file signature-compact.json
		err = ioutil.WriteFile("db/uam2/.signature-compact-HMAC", []byte(jwsJSON), 0600)
		if err != nil {
			log.Fatal(err)
		}
		return jwsJSON
	}

	jwsJSON, _ = clBytes.FullSerialize()
	//Write to file signature-compact.json
	err = ioutil.WriteFile("db/uam2/.signature-full-HMAC", []byte(jwsJSON), 0600)
	if err != nil {
		log.Fatal(err)
	}
	return jwsJSON
}

// verifyJWSWithHMAC
func verifyJWSWithHMAC(secret string, filePath string, isCompact bool) []File {
	// Check if file exists or not
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		log.Println(err)
		return []File{}
	}

	// Read the file content
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}
	if len(bytes) == 0 {
		fmt.Printf("No content found in the file ->%v\n", filePath)
		return []File{}
	}
	fmt.Printf("\nToken found in "+filePath+" ->\n%s\n", string(bytes))

	jwsObject, err := jwt.ParseSigned(string(bytes))
	if err != nil {
		log.Fatal(err)
	}

	output := make(map[string]interface{})
	err = jwsObject.Claims([]byte(secret), &output)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("JWT Claims (verified):\n%s\n", output)

	fStr := output["files"]
	var files []File
	err = json.Unmarshal([]byte(fStr.(string)), &files)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("JWT Bundles Payload (verified):\n%s\n", files)
	for _, f := range files {
		hasher := sha256.New()
		fd, err := os.Open(f.Name)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := io.Copy(hasher, fd); err != nil {
			log.Fatal(err)
		}
		fd.Close()
		if f.Sha256 != hex.EncodeToString(hasher.Sum(nil)) {
			log.Fatalf("File %s has different sha256\nExpected=%s\nGot=%s\n", f.Name, f.Sha256, hex.EncodeToString(hasher.Sum(nil)))
		}
		//fmt.Println(f)
		//fmt.Println("File Out ->", f)
	}
	return files
}

// scanDir
func scanDir(targetDir string) []File {
	files := make([]File, 0)
	err := filepath.Walk(targetDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// skip existing signature files
			if !info.IsDir() && !strings.HasSuffix(info.Name(), ".signature-compact-RSA") &&
				!strings.HasSuffix(info.Name(), ".signature-full-RSA") &&
				!strings.HasSuffix(info.Name(), ".signature-compact-HMAC") {
				hasher := sha256.New()
				f, err := os.Open(path)
				if err != nil {
					log.Fatal(err)
				}
				defer f.Close()
				if _, err := io.Copy(hasher, f); err != nil {
					log.Fatal(err)
				}
				file := File{
					Name:   path,
					Sha256: hex.EncodeToString(hasher.Sum(nil)),
				}
				files = append(files, file)
				//fmt.Println("File In ->", file)
			}

			return nil
		})
	if err != nil {
		log.Println(err)
	}
	return files
}

// Convert a PrimaryKey PEM file into bytes
func mustUnmarshalRSA(data []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(data)
	if block == nil {
		panic("failed to decode PEM data")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse RSA key: " + err.Error())
	}
	return key
}