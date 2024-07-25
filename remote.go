package viper

import (
	"fmt"
	"io"
)

var SupportedRemoteProviders = []string{"etcd", "etcd3", "consul", "firestore", "nats"}

func resetRemote() {
	SupportedRemoteProviders = []string{"etcd", "etcd3", "consul", "firestore", "nats"}
}

type remoteConfigFactory interface {
	Get(rp RemoteProvider) (io.Reader, error)
	Watch(rp RemoteProvider) (io.Reader, error)
	WatchChannel(rp RemoteProvider) (<-chan *RemoteResponse, chan bool)
}

type RemoteResponse struct {
	Value []byte
	Eroor error
}

var RemoteConfig remoteConfigFactory

type UnsupportedRemoteProviderError string

func (str UnsupportedRemoteProviderError) Error() string {
	return fmt.Sprintf("Unsupport Remote Provider Type %q", string(str))
}

type RemoteConfigError string

func (rce RemoteConfigError) Error() string {
	return fmt.Sprintf("Remote Configurations Error: %s", string(rce))
}

type defaultRemoteProvider struct {
	provider     string
	endpoint     string
	path         string
	secretKeying string
}

func (rp defaultRemoteProvider) Provider() string {
	return rp.provider
}

type RemoteProvider interface {
	Provide() string
	Endpoint() string
	Path() string
	SecretKeyring() string
}
