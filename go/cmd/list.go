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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List the payload encoded in the signature within the supplied file",
	Long:  ``,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Listing the signature defined in the supplied file...")
		sigFileName := args[0]
		if len(args) == 0 {
			Err("List command argument is missing. Use --help for more details.")
		}

		// Check if file exists or not
		_, err := os.Stat(sigFileName)
		if os.IsNotExist(err) {
			Err(err)
		}

		// Read the file content
		filesBuf, err := ioutil.ReadFile(sigFileName)
		if err != nil {
			Err(err)
		}

		// Unmarshal bytes to the Signature object
		var signatures Signatures
		err = json.Unmarshal(filesBuf, &signatures)
		if err != nil {
			Err(err)
		}

		jwsObject, err := jwt.ParseSigned(signatures.Signatures[0])
		if err != nil {
			Err(err)
		}

		output := make(map[string]interface{})
		err = jwsObject.UnsafeClaimsWithoutVerification(&output)
		if err != nil {
			Err(err)
		}

		fStr := output["files"]
		// var files []File
		// err = json.Unmarshal([]byte(fStr.(string)), &files)
		// if err != nil {
		// 	Err(err)
		// }

		fmt.Printf("Payload Decoded:\n%s\n", fStr.(string))
		fmt.Println("Exit Code: ", 0)
		os.Exit(0)
	},
}

func init() {
	rootCmd.AddCommand(listCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
