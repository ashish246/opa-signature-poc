/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type File struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha-256"`
}
type Signature struct {
	Signature string `json:"signature"`
	//Files     []File `json:"files"`
}

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create the signature for the given payload",
	Long:  ``,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Creating the signature for the supplied payload or the content of the supplied directory...")
		// Get the flag values
		if len(args) == 0 {
			Err("Create command argument is missing. Use --help for more details.")
		}

		sigFileName := args[0]

		key, _ := cmd.Flags().GetString("key")
		//fmt.Println("key: " + key)
		a, _ := cmd.Flags().GetString("algo")
		//fmt.Println("algo: " + a)
		//sk, _ := cmd.Flags().GetString("secretKey")
		//fmt.Println("secretKey: " + sk)
		p, _ := cmd.Flags().GetString("payload")
		//fmt.Println("payload: " + p)
		td, _ := cmd.Flags().GetString("targetDir")
		//fmt.Println("targetDir: " + td)

		// Validate the options and arguments
		if key == "" {
			Err("--key or -k is required for argument for both RSA and HMAC algos")
		}
		if p == "" && td == "" {
			Err("Either of --payload/-p or the --targetDir/-t is required for the data to sign")
		}

		// Define the payload from the target directory
		var filesBuf []byte
		// Use payload only when target directory is not supplied
		if p != "" && td == "" {
			// Check if file exists or not
			_, err := os.Stat(p)
			if os.IsNotExist(err) {
				Err(err)
			}

			// Read the file content
			filesBuf, err = ioutil.ReadFile(p)
			if err != nil {
				Err(err)
			}
		}

		var err error
		if td != "" {
			files := getPayloadFromDir(td)
			if files == nil {
				Err("No files found in the supplied directory")
			}
			fmt.Printf("Payload generated for signing: \n%s\n", files)
			filesBuf, err = json.Marshal(files)
			if err != nil {
				Err(err)
			}
		}
		if len(filesBuf) == 0 {
			Err("No content found in the file: " + p)
		}

		/**
		Process HMAC Algorithm for Signing
		*/
		if a == "HMAC" {
			CreateJWSWithHMAC(key, filesBuf, true, sigFileName)
			fmt.Println("Exit Code: ", 0)
			os.Exit(0)
		}

		/**
		Process RSA Algorithm for Signing
		*/
		// Generate/Read PrivateKey from the file
		privateKey, err := GetRSAKey(key)
		if err != nil {
			Err(err)
		}
		CreateJWSWithRSA(privateKey, filesBuf, true, sigFileName)
		fmt.Println("Exit Code: ", 0)
		os.Exit(0)
	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// createCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	createCmd.Flags().StringP("key", "k", "", "The path private/public key file used to sign/verify the payload for RSA algo. For HMAC, its the secret key string")
	createCmd.Flags().StringP("algo", "a", "RSA", "The payload to be signed. Possible values are RSA & HMAC. Default is RSA.")
	//createCmd.Flags().StringP("secretKey", "s", "", "The secret key used to sign the payload for HMAC algo.")
	createCmd.Flags().StringP("payload", "p", "", "The payload to be signed. --targetDir/-t will take precedence if --targetDir/-t is also supplied.")
	createCmd.Flags().StringP("targetDir", "t", "", "The target directory whose content needs to be signed. --targetDir will take precedence if --payload/-p is also supplied.")

	_ = createCmd.MarkFlagRequired("key")
}

// createJWSWithRSA
func CreateJWSWithRSA(privateKey *rsa.PrivateKey, filesBuf []byte, isCompact bool, fileName string) {
	// Instantiate a signer using RSASSA-PSS (SHA512) with the given private key.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, &jose.SignerOptions{
		//NonceSource:  nil,
		//EmbedJWK:     false,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": "uam2-opa-poc",
		},
	})
	if err != nil {
		Err(err)
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

	var jwsJson string
	if isCompact {
		jwsJson, _ = clBytes.CompactSerialize()
		// fmt.Printf("[RSA] JWT token generated: \n%s\n", jwsJson)
		// Generate Signature JSON
		signBytes, err := json.Marshal(Signature{
			Signature: jwsJson,
		})
		if err != nil {
			Err(err)
		}
		//Write to file signature-compact.json
		err = ioutil.WriteFile(fileName, signBytes, 0600)
		if err != nil {
			Err(err)
		}
		fmt.Printf("[RSA] Signature file generated: %s\n", fileName)
	}
}

// createJWSWithRSA
func CreateJWSWithHMAC(secret string, filesBuf []byte, isCompact bool, fileName string) {
	// Instantiate a signer using HMAC using SHA-256 with the given private key.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(secret)}, nil)
	if err != nil {
		Err(err)
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

	var jwsJson string
	if isCompact {
		jwsJson, _ = clBytes.CompactSerialize()
		// fmt.Printf("[HMAC] JWT token generated: \n%s\n", jwsJson)
		//Write to file signature-compact.json
		// Generate Signature JSON
		signBytes, err := json.Marshal(Signature{
			Signature: jwsJson,
			//Files:     files,
		})
		err = ioutil.WriteFile(fileName, signBytes, 0600)
		if err != nil {
			Err(err)
		}
		fmt.Printf("[HMAC] Signature file generated: %s\n", fileName)
	}
}

func GetRSAKey(fileName string) (*rsa.PrivateKey, error) {
	// Approach 1 - Generate a random RSA key pair every time
	//privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	//if err != nil {
	//	fmt.Println("Error in main()")
	//	return
	//}

	// Approach 2 - Generate PrivateKey by providing Modulus and Exponent
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

	// Approach 3 - Generate/Read PrivateKey from the file
	pkByte, err := ioutil.ReadFile(fileName)
	if err != nil {
		Err(err)
	}
	return parsePrivateKey(pkByte), nil
}

//parsePrivateKey - Convert a PrimaryKey PEM file into bytes
func parsePrivateKey(data []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(data)
	if block == nil {
		Err("Failed to decode PEM data")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		Err(err)
	}
	return key
}

// getPayloadFromDir
func getPayloadFromDir(targetDir string) []File {
	files := make([]File, 0)
	err := filepath.Walk(targetDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				Err(err)
			}
			// skip existing signature files
			if !info.IsDir() && !strings.HasSuffix(info.Name(), ".DS_Store") {
				hasher := sha256.New()
				f, err := os.Open(path)
				if err != nil {
					Err(err)
				}
				defer f.Close()
				if _, err := io.Copy(hasher, f); err != nil {
					Err(err)
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
		Err(err)
	}
	return files
}
