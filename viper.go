package viper

import "github.com/spf13/afero"

type Viper struct {
	keyDelim    string
	configPaths []string
	fs          afero.Fs
	finder      Finder
	//remoteProviders []*
}
