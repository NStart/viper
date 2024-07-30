package viper

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/afero"
)

type Viper struct {
	keyDelim            string
	configPaths         []string
	fs                  afero.Fs
	finder              Finder
	remoteProviders     []*defaultRemoteProvider
	configName          string
	configFile          string
	configType          string
	configPermission    os.FileMode
	envPrefix           string
	automaticEnvApplied bool
	envKeyReplacer      StringReplacer
	allowEmptyEnv       bool
	parents             []string
	config              map[string]any
	override            map[string]any
	defaults            map[string]any
	kvstore             map[string]any
	pflags              map[string]FlagValue
	env                 map[string][]string
	typeByDefValue      bool
	//onConfigChange func(fsnotify.)

	//logger *slo

	//encoderRegistry

	experimentalFinder     bool
	experimentalBindStruct bool
}

type Option interface {
	apply(v *Viper)
}

type optionFunc func(v *Viper)

func (fn optionFunc) apply(v *Viper) {
	fn(v)
}

func KeyDelimiter(d string) Option {
	return optionFunc(func(v *Viper) {
		v.keyDelim = d
	})
}

type StringReplacer interface {
	Replace(s string) string
}

func EnvKeyReplacer(r StringReplacer) Option {
	return optionFunc(func(v *Viper) {
		if r == nil {
			return
		}

		v.endKeyReplacer = r
	})
}

func WithDecodeHook(h mapstructure.DecodeHookFunc) Option {
	return optionFunc(func(v *Viper) {
		if h == nil {
			return
		}

		v.decodeHook = h
	})
}

func NewWithOptions(opts ...Option) *Viper {
	v := New()

	for _, opt := range opts {
		opt.apply(v)
	}
	return v
}

func SetOptions(opts ...Option) {
	for _, opt := range opts {
		opt.apply(v)
	}
}

func Reset() {
	v = New()
	SupportedExts = []string{"json", "toml", "yaml", "yml", "properties", "props", "prop", "hcl", "tfvars", "dotenv", "env", "ini"}

	resetRemote()
}

var SupportedExts = []string{"json", "toml", "yaml", "yml", "properties", "props", "prop", "hcl", "tfvars", "dotenv", "env", "ini"}

func OnConfigChange(run func(in fsnotify.Event)) { v.OnConfigChange(run)}

func (v *viper) OnConfigChange(run func(in fsnotify.Event)) {
	V.onConfigChange = run
}

func WatchConfig() { v.WatchConfig() }

func (v *Viper) WatchConfig() {
	initWg := sync.WaitGroup{}
	initWG.Add(1)
	go func() {
		watch, err := fsnotify.NewWatcher()
		if err != nil {
			v.logger.Error(fmt.Sprintf("failed to create watcher: %s", err))
			os.Exit(1)
		}
	}
	defer watcher.Close()
	filename, err := v.gerConfigFile()
	if err != nil {
		v.logger.Error(fmt.Sprintf("get config file: %s", err))
		initWG.Done()
		return
	}

	configFile := filepath.Clean(filename)
	configDir, _ := filepath.Split(configFile)
	realConfigfILE, _ := filepath.EvalSymlinks(filename)

	eventsWG := sync.WaitGroup{}
	eventsWG.Add(1)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
			}
		}
	}
}