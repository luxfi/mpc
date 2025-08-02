package config

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/luxfi/mpc/pkg/logger"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type AppConfig struct {
	Consul *ConsulConfig `mapstructure:"consul"`
	NATs   *NATsConfig   `mapstructure:"nats"`

	BadgerPassword string `mapstructure:"badger_password"`
}

// Implement masking serializer AppConfig
func (c AppConfig) MarshalJSONMask() string {
	// clone app config
	c.BadgerPassword = strings.Repeat("*", len(c.BadgerPassword))
	c.Consul.Password = strings.Repeat("*", len(c.Consul.Password))
	c.Consul.Token = strings.Repeat("*", len(c.Consul.Token))
	c.NATs.Password = strings.Repeat("*", len(c.NATs.Password))

	bytes, err := json.Marshal(c)
	if err != nil {
		logger.Error("Failed to marshal app config", err)
	}
	return string(bytes)
}

type ConsulConfig struct {
	Address  string `mapstructure:"address"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Token    string `mapstructure:"token"`
}

type NATsConfig struct {
	URL      string `mapstructure:"url"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

func InitViperConfig() {
	viper.SetConfigName("config") // name of config file (without extension)
	viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")      // optionally look for config in the working directory
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		log.Fatal("Fatal error config file: ", err)
	}

	log.Println("Reading config file:", viper.ConfigFileUsed())
	log.Println("Initialized config successfully!")
}

func LoadConfig() *AppConfig {
	var config AppConfig
	decoderConfig := &mapstructure.DecoderConfig{
		Result:           &config,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	}

	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		log.Fatal("Failed to create decoder", err)
	}

	if err := decoder.Decode(viper.AllSettings()); err != nil {
		log.Fatal("Failed to decode config", err)
	}

	return &config
}
