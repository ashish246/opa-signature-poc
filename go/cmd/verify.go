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
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the supplied signature for the given public key",
	Long:  ``,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Verifying the supplied signature...")
		if len(args) == 0 {
			Err("Verify command argument is missing. Use --help for more details.")
		}

		sigFileName := args[0]
		key, _ := cmd.Flags().GetString("key")
		//fmt.Println("key: " + key)
		a, _ := cmd.Flags().GetString("algo")
		//fmt.Println("algo: " + a)
		td, _ := cmd.Flags().GetString("targetDir")
		//fmt.Println("targetDir: " + td)

		/**
		Process HMAC Algorithm for Signing
		*/
		if a == "HMAC" {
			VerifyJWSWithHMAC(key, sigFileName, td)
			fmt.Println("Exit Code: ", 0)
			os.Exit(0)
		}

		/**
		Process RSA Algorithm for Signing
		*/
		VerifyJWSWithRSA(parsePublicKey(key), sigFileName, td)
		fmt.Println("Exit Code: ", 0)
		os.Exit(0)
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	verifyCmd.Flags().StringP("key", "k", "", "The path of private/public key file used to sign/verify the payload for RSA algo. For HMAC, its the secret key string")
	verifyCmd.Flags().StringP("algo", "a", "RSA", "The payload to be signed. Possible values are RSA & HMAC. Default is RSA.")
	verifyCmd.Flags().StringP("targetDir", "t", "", "The target directory whose content needs to be signed. --targetDir will take precedence if --payload/-p is also supplied.")

	_ = verifyCmd.MarkFlagRequired("key")
	_ = verifyCmd.MarkFlagRequired("targetDir")
}

// verifyJWSWithRSA
func VerifyJWSWithRSA(publicKey *rsa.PublicKey, filePath string, targetDir string) {
	// Check if file exists or not
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		Err(err)
	}

	// Read the file content
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		Err(err)
	}
	if len(bytes) == 0 {
		Err("[RSA] No content found in the file: " + filePath)
	}

	// Unmarshal bytes to the Signature object
	var signatures Signatures
	err = json.Unmarshal(bytes, &signatures)
	if err != nil {
		Err(err)
	}
	//fmt.Printf("[RSA] JWT token found in the file "+filePath+": \n%s\n", signatures.Signature)

	jwsObject, err := jwt.ParseSigned(signatures.Signatures[0])
	if err != nil {
		Err(err)
	}

	output := make(map[string]interface{})
	err = jwsObject.Claims(publicKey, &output)
	if err != nil {
		Err(err)
	}
	fmt.Printf("[RSA] Signature valid flag: TRUE\n")

	isPayloadValid := verifyPayloadFiles(output["files"], targetDir)
	if !isPayloadValid {
		Err("SHA hash of one or more files could not be verified")
	}
	fmt.Println("[RSA] SHA hash of all the files is verified successfully")
}

// verifyJWSWithHMAC
func VerifyJWSWithHMAC(secret string, filePath string, targetDir string) {
	// Check if file exists or not
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		Err(err)
	}

	// Read the file content
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		Err(err)
	}
	if len(bytes) == 0 {
		Err("[HMAC] No content found in the file: " + filePath)
	}
	// Unmarshal bytes to the Signature object
	var signatures Signatures
	err = json.Unmarshal(bytes, &signatures)
	if err != nil {
		Err(err)
	}
	//fmt.Printf("[HMAC] JWT token found in the file "+filePath+": \n%s\n", signatures.Signature)

	jwsObject, err := jwt.ParseSigned(signatures.Signatures[0])
	if err != nil {
		Err(err)
	}

	output := make(map[string]interface{})
	err = jwsObject.Claims([]byte(secret), &output)
	if err != nil {
		Err(err)
	}
	fmt.Printf("[HMAC] Signature valid flag: TRUE\n")

	isPayloadValid := verifyPayloadFiles(output["files"], targetDir)
	if !isPayloadValid {
		Err("SHA hash of one or more files could not be verified")
	}
	fmt.Println("[HMAC] SHA hash of all the files is verified successfully")
}

// verifyPayloadFiles
func verifyPayloadFiles(payload interface{}, targetDir string) bool {

	// This extra marshalling helps you unmarshal the interface{} type into []File object
	payloadJSON, err := json.MarshalIndent(payload, "", " ")
	if err != nil {
		Err(err)
	}
	fmt.Printf("Payload Decoded:\n%s\n", payloadJSON)
	// Get the source files
	var sourceFiles []File
	err = json.Unmarshal(payloadJSON, &sourceFiles)
	if err != nil {
		Err(err)
	}

	// Get the target files
	targetFiles := make([]File, 0)
	err = filepath.Walk(targetDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				Err(err)
			}
			// Hash JSON files
			if !info.IsDir() && !strings.HasSuffix(info.Name(), ".DS_Store") && strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
				hash, err := hashJSON(path)
				if err != nil {
					Err(err)
				}
				file := File{
					Name:      path,
					Hash:      hash,
					Algorithm: "sha-256",
				}
				targetFiles = append(targetFiles, file)
			}
			// skip existing signature files and JSON files
			if !info.IsDir() && !strings.HasSuffix(info.Name(), ".DS_Store") && !strings.HasSuffix(strings.ToLower(info.Name()), ".json") {
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
					Name:      path,
					Hash:      hex.EncodeToString(hasher.Sum(nil)),
					Algorithm: "sha-256",
				}
				targetFiles = append(targetFiles, file)
				//fmt.Println("File In ->", file)
			}
			return nil
		})
	if err != nil {
		Err(err)
	}

	// Check if there are any additional files in target directory
	for _, tf := range targetFiles {
		extra := true
		for _, sf := range sourceFiles {
			if tf.Name == sf.Name {
				extra = false
			}
		}

		if extra {
			Err("Additional file " + tf.Name + " found in the target directory")
		}
	}

	// Validate source against the target directory
	for _, sf := range sourceFiles {
		var exists bool
		for _, tf := range targetFiles {
			if tf.Name == sf.Name {
				exists = true
				if sf.Hash != tf.Hash {
					Err("File " + sf.Name + " has different sha256\nExpected=" + sf.Hash + "\nGot=" + tf.Hash)
				}
			}
		}
		if !exists {
			Err("File " + sf.Name + " in the payload could not be found in target directory")
		}
	}

	return true
}

//parsePrivateKey - Convert a PrimaryKey PEM file into bytes
func parsePublicKey(fileName string) *rsa.PublicKey {
	pubByte, err := ioutil.ReadFile(fileName)
	if err != nil {
		Err(err)
	}
	block, _ := pem.Decode(pubByte)
	if block == nil {
		Err("Failed to decode PEM data")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		Err(err)
	}
	return key.(*rsa.PublicKey)
}
