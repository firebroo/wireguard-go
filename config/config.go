package config

import (
	"os"
	"fmt"
	"log"
	"encoding/json"
	"io/ioutil"
)
type CONFIG struct {
	Hosts []string `json:"hosts"`
	Auth  string   `json:"auth"`
}

var Config CONFIG

func init(){
	LoadConfig()
}

func LoadConfig(){
	jsonFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalln("Cannot open config file", err)
	}
	defer jsonFile.Close()
	jsonData, err := ioutil.ReadAll(jsonFile)
	if err!= nil {
		fmt.Println("error reading json file")
		return
	}
	Config = CONFIG{}
	json.Unmarshal(jsonData,&Config)
}
