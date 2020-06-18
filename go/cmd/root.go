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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "go-opasign",
	Aliases: []string{"go-os"},
	Short:   "Root command to execute the GO implementation of OPA signature POC",
	Long:    ``,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("One of the subcommand is required to execute the command. Use --help for more details.")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/...yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".." (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName("..")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func Err(msg interface{}) {
	fmt.Println("Error occurred: ", msg)
	fmt.Println("Exit Code: ", 1)
	os.Exit(1)
}

func hashJSON(path string) (string, error) {
	fileByte, err := ioutil.ReadFile(path)
	if err != nil {
		Err(err)
	}

	data := make(map[string]interface{})
	err = json.Unmarshal(fileByte, &data)
	if err != nil {
		Err(err)
	}

	// var b bytes.Buffer
	// walk(data, &b)
	// s2 := b.Bytes()
	// fmt.Printf("json marshal: %s\n", string(fileByte))
	// fmt.Printf("synt marshal: %s\n", string(s2))

	h := sha256.New()
	h.Write(fileByte)
	d1 := h.Sum(nil)
	fmt.Printf("json digest is: %s\n", hex.EncodeToString(d1))

	d2 := digest(data)
	finalHash := hex.EncodeToString(d2)
	fmt.Printf("synt digest is: %s\n", finalHash)

	return finalHash, nil
}

func digest(v interface{}) []byte {
	h := sha256.New()
	walk(v, h)
	return h.Sum(nil)
}

func walk(v interface{}, h io.Writer) {
	switch x := v.(type) {
	case map[string]interface{}:
		h.Write([]byte("{"))
		var keys []string
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, key := range keys {
			if i > 0 {
				h.Write([]byte(","))
			}
			h.Write(encodePrimitive(key))
			h.Write([]byte(":"))
			walk(x[key], h)
		}
		h.Write([]byte("}"))
	case []interface{}:
		h.Write([]byte("["))
		for i, e := range x {
			if i > 0 {
				h.Write([]byte(","))
			}
			walk(e, h)
		}
		h.Write([]byte("]"))
	default:
		h.Write(encodePrimitive(x))
	}
}
func encodePrimitive(v interface{}) []byte {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.Encode(v)
	return []byte(strings.Trim(string(buf.Bytes()), "\n"))
}
