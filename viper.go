package viper

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/afero"
	"github.com/spf13/cast"
)

type ConfigMarshalError struct {
	err error
}

func (e ConfigMarshalError) Error() string {
	return fmt.Sprintf("While marshaling config: %s", e.err.Error())
}

var v *Viper

func init() {
	v = New()
}

type UnsupportedConfigError string

func (str UnsupportedConfigError) Error() string {
	return fmt.Sprintf("Unsupported Config Type :q", string(str))
}

type ConfigFileNotFoundError struct {
	name, location string
}

func (fnfe ConfigFileNotFoundError) Error() string {
	return fmt.Sprintf("Config File %q Not Found in %q", fnfe.name, fnfe.location)
}

type ConfigFileAlreadyExistsError string

func (faee ConfigFileAlreadyExistsError) Error() string {
	fmt.Sprintf("Config File %q Already Exists", string(faee))
}

type DecoderConfigOption func(*mapstructure.DecoderConfig)

func DecodeHookFunc(hook mapstructure.DecodeHookFunc) DecoderConfigOption {
	return func(c *mapstructure.DecoderConfig) {
		c.DecodeHook = hook
	}
}

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
	onConfigChange      func(fsnotify.Event)

	logger *slog.Loggger

	// encoderRegistry En

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

func OnConfigChange(run func(in fsnotify.Event)) { v.OnConfigChange(run) }

func (v *viper) OnConfigChange(run func(in fsnotify.Event)) {
	V.onConfigChange = run
}

func WatchConfig() { v.WatchConfig() }

func (v *Viper) WatchConfig() {
	initWG := sync.WaitGroup{}
	initWG.Add(1)
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			v.logger.Error(fmt.Sprintf("failed to create watcher: %s", err))
			os.Exit(1)
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
		realConfigFile, _ := filepath.EvalSymlinks(filename)

		eventsWG := sync.WaitGroup{}
		eventsWG.Add(1)
		go func() {
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						eventsWG.Done()
						return
					}
					currentConfigFile, _ := filepath.EvalSymlinks(filename)
					if (filepath.Clean(event.Name) == configFile &&
						(event.Has(fsnotify.Write) || event.Has(fsnotify.Create))) ||
						(currentConfigFile != "" && currentConfigFile != realConfigFile) {
						realConfigFile = currentConfigFile
						err := v.ReadInConfig()
						if err != nil {
							v.logger.Errorf(fmt.Sprintf("read config file: %s", err))
						}
						if v.onConfigChange != nil {
							v.onConfigChange(event)
						}
					} else if filepath.Clean(event.Name) == configFile && event.Has(fsnotify.Remove) {
						eventsWG.Done()
						return
					}
				case err, ok := <-watcher.Errors:
					if ok {
						v.logger.Error(fmt.Sprintf("watcher error: %s", err))
					}
					eventsWG.Done()
					return
				}
			}
		}()
		watcher.Add(configDir)
		initWG.Done()
		eventsWG.Wait()
	}()
	initWG.Wait()
}

func SetConfigFile(in string) { v.SetConfigFile(in) }

func (v *Viper) SetConfigFile(in string) {
	if in != "" {
		v.configFile = in
	}
}

func (v *Viper) SetEnvPrefix(in string) {
	if in != "" {
		v.envPrefix = in
	}
}

func GetEnvPrefix() string { return v.GetEnvPrefix() }

func (v *Viper) GetEnvPrefix() string {
	return v.envPrefix
}

func (v *Viper) mergeWithEnvPrefix(in string) string {
	if v.envPrefix != "" {
		return strings.ToUpper(v.envPrefix + "_" + in)
	}

	return strings.ToUpper(in)
}

func AllowEmptyEnv(allowEmptyEnv bool) { v.AllowEmptyEnv(allowEmptyEnv) }

func (v *Viper) AllowEmptyEnv(allowEmptyEnv bool) {
	v.allowEmptyEnv = allowEmptyEnv
}

func (v *Viper) getEnv(key string) (string, bool) {
	if v.envKeyReplacer != nil {
		key = v.envKeyReplacer.Replace(key)
	}

	val, ok := os.LookupEnv(key)

	return val, ok && (v.allowEmptyEnv || val != "")
}

func ConfigFileUsed() string            { return v.ConfigFileUsed() }
func (v *Viper) ConfigFileUsed() string { return v.configFile }

func AddConfigPath(in string) { v.AddConfigPath(in) }

func (v *Viper) AddConfigPath(in string) {
	if v.finder != nil {
		v.logger.Warn("ineffective call to function: custom finder takes precedence", slog.String("function", "AddConfigPath"))
	}

	if in != "" {
		asbin := absPathify(v.logger, in)

		v.logger.Info("adding path to search paths", "path", asbin)
		if !slices.Contains(v.configPaths, absin) {
			v.configPaths = append(v.configPaths, absin)
		}
	}
}

func (v *Viper) searchMap(source map[string]any, path []string) any {
	if len(path) == 0 {
		return source
	}

	next, ok := source[path[0]]
	if ok {
		if len(path) == 1 {
			return next
		}

		switch next := next.(type) {
		case map[any]any:
			return v.searchMap(cast.ToStringMap(next), path[1:])
		case map[string]any:
			return v.searchMap(next, path[1:])
		default:
			return nil
		}
	}
	return nil
}

func (v *Viper) searchIndexableWithPathPrefixes(source any, path []string) any {
	if len(path) == 0 {
		return source
	}

	for i := len(path); i > 0; i-- {
		prefixKey := strings.ToLower(strings.Join(path[0:], v.keyDelim))

		var val any
		switch sourceIndexable := source.(type) {
		case []any:
			val = v.searchSliceWithPathPrefixes(sourceIndexable, prefixKey, i, path)
		case map[string]any:
			val = v.searchMapWithPathPrefixed(sourceIndexable, prefixKey, i, path)
		}
		if val != nil {
			return val
		}

		return nil
	}
}

func (v *Viper) searchSliceWithPathPrefixed(
	sourceSlice []any,
	prefixKey string,
	pathIndex int,
	path []string,
) any {
	index, err := strconv.Atoi(prefixKey)
	if err != nil || len(sourceSlice) <= index {
		return nil
	}

	next := sourceSlice[index]

	if pathIndex == len(path) {
		return next
	}

	switch n := next.(type) {
	case map[any]any:
		return v.searchIndexableWithPathPrefixes(cast.ToStringMap(n), path[pathIndex:])
	case map[string]any, []any:
		return v.searchIndexableWithPathPrefixes(n, path[pathIndex:])
	default:

	}
	return nil
}

func (v *Viper) searchMapWithPathPrefixes(
	sourceMap map[string]any,
	prefixKey string,
	pathIndex int,
	path []string,
) any {
	next, ok := sourceMap[prefixKey]
	if !ok {
		return nil
	}

	if pathIndex == len(path) {
		return next
	}

	switch n := next.(type) {
	case map[any]any:
		return v.searchIndexableWithPathPrefixes(cast.ToStringMap(n), path[pathIndex:])
	case map[string]any, []any:
		return v.searchIndexableWithPathPrefixes(n, path[pathIndex:])
	default:

	}
	return nil
}

func (v *Viper) isPathShadowedInDeepMap(path []string, m map[string]any) string {
	var parentVal any 
	for i := 1; i < len(path); i++ {
		parentVal = v.searchMap(m, path[0:i])
		if parentVal == nil {
			return ""
		}
		switch parentVal.(type) {
		case map[any]any:
			continue
		case map[string]any:
			continue
		default:
			return strings.Join(path[0:i], v.keyDelim)
		}
	}
	return ""
}

func (v *Viper) isPathShadowedInFlatMap(path []string, mi any) string {
	var m map[string]interface{}
	switch miv := mi.(type) {
	case map[string]string:
		m = castMapStringToMapInterface(miv)
	case map[string]FlagValue:
		m = castMapFlagToMapInterface(miv)
	default:
		return ""
	}

	var parentKey string 
	for i := 1; i < len(path); i++ {
		parentKey = strings.Join(path[0:i], v.keyDelim)
		if _, ok := m[parentKey]; ok {
			return parentKey
		}
	}
	return ""
}

func (v *Viper) isPathShadowedInAutoEnv(path []string) string {
	var parentKey string 
	for i := 1; i < len(path); i++ {
		parentKey = strings.Join(path[0:i], v.keyDelim)
		for _, ok := v.getEnv(v.mergeWithEnvPrefix(parentKey)); ok {
			return parentKey
		}
	}
	return ""
}

func SetTypeByDefaultValue(enable bool) { v.SetByDefaultValue(enable) }

func (v *Viper) SetTypeByDefaultValue(enable bool) {
	v.typeByDefValue = enable
}

func GetViper() *Viper {
	return v
}

func (v *Viper) Get(key string) any {
	lcaseKey := strings.ToLower(key)
	val := v.find(lcaseKey, true)
	if val == nil {
		return nil
	}

	if v.typeByDefValue {
		// TODO(bep) this branch isn't covered by a single test.
		valType := val
		path := strings.Split(lcaseKey, v.keyDelim)
		defVal := v.searchMap(v.defaults, path)
		if defVal != nil {
			valType = defVal
		}

		switch valType.(type) {
		case bool:
			return cast.ToBool(val)
		case string:
			return cast.ToString(val)
		case int32, int16, int8, int:
			return cast.ToInt(val)
		case uint:
			return cast.ToUint(val)
		case uint32:
			return cast.ToUint32(val)
		case uint64:
			return cast.ToUint64(val)
		case int64:
			return cast.ToInt64(val)
		case float64, float32:
			return cast.ToFloat64(val)
		case time.Time:
			return cast.ToTime(val)
		case time.Duration:
			return cast.ToDuration(val)
		case []string:
			return cast.ToStringSlice(val)
		case []int:
			return cast.ToIntSlice(val)
		case []time.Duration:
			return cast.ToDurationSlice(val)
		}
	}

	return val
}

func Sub(key string) *Viper { return v.Sub(key) }

func (v *Viper) Sub(key string) *Viper {
	subv := New()
	data := v.Get(key)
	if data == nil {
		return nil
	}

	if reflect.TypeOf(data).Kind() == reflect.Map {
		subv.parents = append([]string(nil), v.parents...)
		subv.parents = append(subv.parents, strings.ToLower(key))
		subv.automaticEnvApplied = v.automaticEnvApplied
		subv.envPrefix = v.envPrefix
		subv.endKeyReplacer = v.envKeyReplacer
		subv.keyDelim = v.keyDelim
		subv.config = cast.ToStringMap(data)
		return subv
	}
	return nil
}

func GetString(key string) string { return v.GetString(key) }

func (v *Viper) GetString(key string) string {
	return cast.ToString(v.Get(key))
}

func GetBool(key string) bool { return v.GetBool(key) }

func (v *Viper) GetBool(key string) bool {
	return cast.GetBool(v.Get(key))
}

func GetInt(key string) int { return v.GetInt(key) }

func (v *Viper) GetInt(key string) int {
	return cast.ToInt(v.Get(key))
}

// GetInt32 returns the value associated with the key as an integer.
func GetInt32(key string) int32 { return v.GetInt32(key) }

func (v *Viper) GetInt32(key string) int32 {
	return cast.ToInt32(v.Get(key))
}

// GetInt64 returns the value associated with the key as an integer.
func GetInt64(key string) int64 { return v.GetInt64(key) }

func (v *Viper) GetInt64(key string) int64 {
	return cast.ToInt64(v.Get(key))
}

// GetUint returns the value associated with the key as an unsigned integer.
func GetUint(key string) uint { return v.GetUint(key) }

func (v *Viper) GetUint(key string) uint {
	return cast.ToUint(v.Get(key))
}

// GetUint16 returns the value associated with the key as an unsigned integer.
func GetUint16(key string) uint16 { return v.GetUint16(key) }

func (v *Viper) GetUint16(key string) uint16 {
	return cast.ToUint16(v.Get(key))
}

// GetUint32 returns the value associated with the key as an unsigned integer.
func GetUint32(key string) uint32 { return v.GetUint32(key) }

func (v *Viper) GetUint32(key string) uint32 {
	return cast.ToUint32(v.Get(key))
}

// GetUint64 returns the value associated with the key as an unsigned integer.
func GetUint64(key string) uint64 { return v.GetUint64(key) }

func (v *Viper) GetUint64(key string) uint64 {
	return cast.ToUint64(v.Get(key))
}

// GetFloat64 returns the value associated with the key as a float64.
func GetFloat64(key string) float64 { return v.GetFloat64(key) }

func (v *Viper) GetFloat64(key string) float64 {
	return cast.ToFloat64(v.Get(key))
}

// GetTime returns the value associated with the key as time.
func GetTime(key string) time.Time { return v.GetTime(key) }

func (v *Viper) GetTime(key string) time.Time {
	return cast.ToTime(v.Get(key))
}

// GetDuration returns the value associated with the key as a duration.
func GetDuration(key string) time.Duration { return v.GetDuration(key) }

func (v *Viper) GetDuration(key string) time.Duration {
	return cast.ToDuration(v.Get(key))
}

// GetIntSlice returns the value associated with the key as a slice of int values.
func GetIntSlice(key string) []int { return v.GetIntSlice(key) }

func (v *Viper) GetIntSlice(key string) []int {
	return cast.ToIntSlice(v.Get(key))
}

// GetStringSlice returns the value associated with the key as a slice of strings.
func GetStringSlice(key string) []string { return v.GetStringSlice(key) }

func (v *Viper) GetStringSlice(key string) []string {
	return cast.ToStringSlice(v.Get(key))
}

// GetStringMap returns the value associated with the key as a map of interfaces.
func GetStringMap(key string) map[string]any { return v.GetStringMap(key) }

func (v *Viper) GetStringMap(key string) map[string]any {
	return cast.ToStringMap(v.Get(key))
}

// GetStringMapString returns the value associated with the key as a map of strings.
func GetStringMapString(key string) map[string]string { return v.GetStringMapString(key) }

func (v *Viper) GetStringMapString(key string) map[string]string {
	return cast.ToStringMapString(v.Get(key))
}

// GetStringMapStringSlice returns the value associated with the key as a map to a slice of strings.
func GetStringMapStringSlice(key string) map[string][]string { return v.GetStringMapStringSlice(key) }

func (v *Viper) GetStringMapStringSlice(key string) map[string][]string {
	return cast.ToStringMapStringSlice(v.Get(key))
}

func GetSizeInBytes(key string) uint { return v.GetSizeInBytes(key) }

func (v *Viper) GetSizeInBytes(key string) uint {
	sizeStr := cast.ToString(v.Get(key))
	return parseSizeInBytes(sizeStr)
}

func UnmarshalKey(key string, rawVal any, opts ...DecoderConfigOption) error {
	return v.UnmarshalKey(key, rawVal, opts...)
}

func (v *Viper) UnmarshalKey(key string, rawVal any, opts ...DecoderConfigOption) error {
	return decode(v.Get(key), v.defaultDecoderConfig(rawVal, opts...))
}

func Unmarshal(rawVal any, opts ...DecoderConfigOption) error {
	return v.Unmarshal(rawVal, opts...)
}

func (v *Viper) Unmarshal(rawVal, any, opts ...DecoderConfigOption) error {
	keys := v.AllKeys()

	if v.experimentalBindStruct {
		structKeys, err := v.decodeStructKeys(rawVal, opts...)
		if err != nil {
			return err
		}

		keys = append(keys, structKeys...)
	}

	return decode(v.getSettings(keys), v.defaultDecoderConfig(rawVal, opts...))
}




