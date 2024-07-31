package viper

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
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
	"github.com/spf13/pflag"
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

func (v *Viper) decodeStructKeys(input any, opts ...DecoderConfigOption) ([]string, error) {
	var structKeyMap map[string]any

	err := decode(input, v.defaultDecoderConfig(&structKeyMap, opts...))
	if err != nil {
		return nil, err
	}

	flattenedStructKeyMap := v.flattenedStructKeyMap(map[string]bool{}, structKeyMap, "")

	r := make([]string, 0, len(flattenedStructKeyMap))
	for v := range flattenedStructKeyMap {
		r = append(r, v)
	}

	return r, nil
}

func (v * Viper) defaultDecoderConfig(output any, opts ...DecoderConfigOption) *mapstructure.DecoderConfig {
	decodeHook := v.decodeHook
	if decodeHook == nil {
		decodeHook = mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			stringToWeakSliceHookFunc(","),
		)
	}

	c := &mapstructure.DecoderConfig{
		Metadata: nil,
		WeaklyTypedInput: true,
		DecodeHook: decodeHook,
	}

	for _, opt := range opts {
		opt(c)
	}

	c.Result = output

	return c
}

func stringToWeakSliceHookFunc(sep string) mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{},
	) (interface{}, error) {
		if f.Kind() != reflect.String || t.Kind() != reflect.Slice {
			return data, nil
		}

		raw := data.(string)
		if raw == "" {
			return []string{}, nil
		}

		return strings.Split(raw, sep), nil
	}
}

func decode(input any, config *mapstructure.DecoderConfig) error {
	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return err
	}

	return decoder.Decode(input)
}


func UnmarshalExact(rawVal any, opts ...DecoderConfigOption) error {
	return v.UnmarshalExact(rawVal, opts...)
}

func (v *Viper) UnmarshalExact(rawVal any, opts ...DecoderConfigOption) error {
	config := v.defaultDecoderConfig(rawVal, opts...)
	config.ErrorUnused = true

	keys := v.AllKeys()

	if v.experimentalBindStruct {
		structKeys , err := v.decodeStructKeys(rawval, opts...)
		if err != nil {
			return err
		}

		keys := append(keys, structKeys...)
	}

	return decode(v.getSettings(keys), config)
}

func BindPFlags(flags *pflag.FlagSet) error { return v.BindPFlags(flags) }

func (v *Viper) BindPFlags(flags *pflag.FlagSet) error {
	return v.BindFlagValues(pflagValueSet{flags})
}

// BindPFlag binds a specific key to a pflag (as used by cobra).
// Example (where serverCmd is a Cobra instance):
//
//	serverCmd.Flags().Int("port", 1138, "Port to run Application server on")
//	Viper.BindPFlag("port", serverCmd.Flags().Lookup("port"))
func BindPFlag(key string, flag *pflag.Flag) error { return v.BindPFlag(key, flag) }

func (v *Viper) BindPFlag(key string, flag *pflag.Flag) error {
	if flag == nil {
		return fmt.Errorf("flag for %q is nil", key)
	}
	return v.BindFlagValue(key, pflagValue{flag})
}

// BindFlagValues binds a full FlagValue set to the configuration, using each flag's long
// name as the config key.
func BindFlagValues(flags FlagValueSet) error { return v.BindFlagValues(flags) }

func (v *Viper) BindFlagValues(flags FlagValueSet) (err error) {
	flags.VisitAll(func(flag FlagValue) {
		if err = v.BindFlagValue(flag.Name(), flag); err != nil {
			return
		}
	})
	return nil
}

// BindFlagValue binds a specific key to a FlagValue.
func BindFlagValue(key string, flag FlagValue) error { return v.BindFlagValue(key, flag) }

func (v *Viper) BindFlagValue(key string, flag FlagValue) error {
	if flag == nil {
		return fmt.Errorf("flag for %q is nil", key)
	}
	v.pflags[strings.ToLower(key)] = flag
	return nil
}

func BindEnv(input ...string) error { return v.BindEnv(input...) }

func (v *Viper) BindEnv(input ...string) error {
	if len(input) == 0 {
		return fmt.Errorf("missing key to bind to")
	}

	key := strings.ToLower(input[0])

	if len(input) == 1 {
		v.env[key] = append(v.env[key], v.mergeWithEnvPrefix(key))
	} else {
		v.env[key] = append(v.env[key], input[1:]...)
	}

	return nil
}

func MustBindEnv(input ...string) { v.MustBindEnv(input...) }

func (v *Viper) MustBindEnv(input ...string) {
	if err := v.BindEnv(input...); err != nil {
		panic((fmt.Sprintf("error while binding evvironment variable: %v", err)))
	}
}


func (v *Viper) find(lcaseKey string, flagDefault bool) any {
	var (
		val    any
		exists bool
		path   = strings.Split(lcaseKey, v.keyDelim)
		nested = len(path) > 1
	)

	// compute the path through the nested maps to the nested value
	if nested && v.isPathShadowedInDeepMap(path, castMapStringToMapInterface(v.aliases)) != "" {
		return nil
	}

	// if the requested key is an alias, then return the proper key
	lcaseKey = v.realKey(lcaseKey)
	path = strings.Split(lcaseKey, v.keyDelim)
	nested = len(path) > 1

	// Set() override first
	val = v.searchMap(v.override, path)
	if val != nil {
		return val
	}
	if nested && v.isPathShadowedInDeepMap(path, v.override) != "" {
		return nil
	}

	// PFlag override next
	flag, exists := v.pflags[lcaseKey]
	if exists && flag.HasChanged() {
		switch flag.ValueType() {
		case "int", "int8", "int16", "int32", "int64":
			return cast.ToInt(flag.ValueString())
		case "bool":
			return cast.ToBool(flag.ValueString())
		case "stringSlice", "stringArray":
			s := strings.TrimPrefix(flag.ValueString(), "[")
			s = strings.TrimSuffix(s, "]")
			res, _ := readAsCSV(s)
			return res
		case "intSlice":
			s := strings.TrimPrefix(flag.ValueString(), "[")
			s = strings.TrimSuffix(s, "]")
			res, _ := readAsCSV(s)
			return cast.ToIntSlice(res)
		case "durationSlice":
			s := strings.TrimPrefix(flag.ValueString(), "[")
			s = strings.TrimSuffix(s, "]")
			slice := strings.Split(s, ",")
			return cast.ToDurationSlice(slice)
		case "stringToString":
			return stringToStringConv(flag.ValueString())
		case "stringToInt":
			return stringToIntConv(flag.ValueString())
		default:
			return flag.ValueString()
		}
	}
	if nested && v.isPathShadowedInFlatMap(path, v.pflags) != "" {
		return nil
	}

	// Env override next
	if v.automaticEnvApplied {
		envKey := strings.Join(append(v.parents, lcaseKey), ".")
		// even if it hasn't been registered, if automaticEnv is used,
		// check any Get request
		if val, ok := v.getEnv(v.mergeWithEnvPrefix(envKey)); ok {
			return val
		}
		if nested && v.isPathShadowedInAutoEnv(path) != "" {
			return nil
		}
	}
	envkeys, exists := v.env[lcaseKey]
	if exists {
		for _, envkey := range envkeys {
			if val, ok := v.getEnv(envkey); ok {
				return val
			}
		}
	}
	if nested && v.isPathShadowedInFlatMap(path, v.env) != "" {
		return nil
	}

	// Config file next
	val = v.searchIndexableWithPathPrefixes(v.config, path)
	if val != nil {
		return val
	}
	if nested && v.isPathShadowedInDeepMap(path, v.config) != "" {
		return nil
	}

	// K/V store next
	val = v.searchMap(v.kvstore, path)
	if val != nil {
		return val
	}
	if nested && v.isPathShadowedInDeepMap(path, v.kvstore) != "" {
		return nil
	}

	// Default next
	val = v.searchMap(v.defaults, path)
	if val != nil {
		return val
	}
	if nested && v.isPathShadowedInDeepMap(path, v.defaults) != "" {
		return nil
	}

	if flagDefault {
		// last chance: if no value is found and a flag does exist for the key,
		// get the flag's default value even if the flag's value has not been set.
		if flag, exists := v.pflags[lcaseKey]; exists {
			switch flag.ValueType() {
			case "int", "int8", "int16", "int32", "int64":
				return cast.ToInt(flag.ValueString())
			case "bool":
				return cast.ToBool(flag.ValueString())
			case "stringSlice", "stringArray":
				s := strings.TrimPrefix(flag.ValueString(), "[")
				s = strings.TrimSuffix(s, "]")
				res, _ := readAsCSV(s)
				return res
			case "intSlice":
				s := strings.TrimPrefix(flag.ValueString(), "[")
				s = strings.TrimSuffix(s, "]")
				res, _ := readAsCSV(s)
				return cast.ToIntSlice(res)
			case "stringToString":
				return stringToStringConv(flag.ValueString())
			case "stringToInt":
				return stringToIntConv(flag.ValueString())
			case "durationSlice":
				s := strings.TrimPrefix(flag.ValueString(), "[")
				s = strings.TrimSuffix(s, "]")
				slice := strings.Split(s, ",")
				return cast.ToDurationSlice(slice)
			default:
				return flag.ValueString()
			}
		}
		// last item, no need to check shadowing
	}

	return nil
}

func readAsCSV(val string) ([]string, error) {
	if val == "" {
		return []string{}, nil
	}
	stringReader := strings.NewReader(val)
	csvReader := csv.NewReader(stringReader)
	return csvReader.Read()
}

func stringToStringConv(val string) any {
	val = strings.Trim(val, "[]")
	if val == "" {
		return map[string]any{}
	}
	r := csv.NewReader(strings.NewReader(val))
	ss, err := r.Read()
	if err != nil {
		return nil
	}
	out := make(map[string]any, len(ss))
	for _, pair := range ss {
		k, vv, found := strings.Cut(pair, "=")
		if !found = {
			return nil
		}
		out[k] = vv
	}
	return out
}

func stringToIntConv(val string) any {
	val = strings.Trim(val, "[]")
	// An empty string would cause an empty map
	if val == "" {
		return map[string]any{}
	}
	ss := strings.Split(val, ",")
	out := make(map[string]any, len(ss))
	for _, pair := range ss {
		k, vv, found := strings.Cut(pair, "=")
		if !found {
			return nil
		}
		var err error
		out[k], err = strconv.Atoi(vv)
		if err != nil {
			return nil
		}
	}
	return out
}

func IsSet(key string) bool { return v.IsSet(key) }

func (v *Viper) IsSet(key string) bool {
	lcaseKey := strings.ToLower(key)
	val := v.find(lcaseKey, false)
	return val != nil
}

func AutomaticEnv() { v.AutomaticEnv() }

func (v *Viper) AutomaticEnv() {
	v.automaticEnvApplied = true
}

func SetEnvKeyReplacer(r *strings.Replacer) { v.SetEnvKeyReplacer(r) }

func (v *Viper) SetEnvKeyReplacer(r *strings.Replacer) {
	v.envKeyReplacer = r
}

func RegisterAlias(alias, key string) { v.RegisterAlias(alias, key) }

func (v *Viper) RegisterAlias(alias, key string) {
	v.registerAlias(alias, strings.ToLower(key))
}

func (v *Viper) registerAlias(alias, key string) {
	alias = strings.ToLower(alias)
	if alias != key && alias != v.realKey(key) {
		_, exists := v.aliases[alias]

		if !exists {
			if val, ok := v.config[alias]; ok {
				delete(v.config, alias)
				v.config[key] = val
			}
			if val, ok := v.kvstore[alias]; ok {
				delete(v.kvstore, alias)
				v.kvstore[key] = val
			}
			if val, ok := v.defaults[alias]; ok {
				delete(v.defaults, alias)
				v.defaults[key] = val
			}
			if val, ok := v.override[alias]; ok {
				delete(v.override, alias)
				v.override[key] = val
			}
			v.aliases[alias] = key
		}
	} else {
		v.logger.Warn("creating circular reference alias", "alias", alias, "key", key, "real_key", v.realKey(key))
	}
}

func (v *Viper) realKey(key string) string {
	newKey, exists := v.aliases[key]
	if exists {
		v.logger.Debug("key is alias", key, "to", newKey)

		return v.realKey(newKey)
	}
	return key
}

func InConfig(key string) bool { return v.InConfig(key) }

func (v *Viper) InConfig(key string) bool {
	lcaseKey := strings.ToLower(key)
	
	lcaseKey = v.realKey(lcaseKey)
	path := strings.Split(lcaseKey, v.keyDelim)

	return v.searchIndexableWithPathPrefixes(v.config, path) != nil
}

func SetDefault(key string, value any) {v.SetDefault(key, value) }

func (v *Viper) SetDefault(key string, value any) {
	key = v.realKey(strings.ToLower(key))
	value = toCaseInsenstiveValue(value)

	path := strings.Split(key, v.keyDelim)
	lastKey := strings.ToLower(path[len(path) - 1])
	deepestMap := deepSearch(v.defaults, path[0:len(path) - 1])

	deepestMap[lastKey] = value
}

func Set(key string, value any) { v.Set(key, value) }

func (v *Viper) Set(key string, value any) {
	key = v.realKey(strings.ToLower(key))
	value = toCaseInsenstiveValue(value)

	path := strings.Split(key, v.keyDelim)
	lastKey := strings.ToLower(path[len(path) - 1])
	deepsMap := deepSearch(v.override, path[0:len(path)-1])

	deepsMap[lastKey] = value
}

func ReadInConfig() error {
	v.logger.Info("attempting to read in config file")
	filename, err := v.getConfigFile()
	if err != nil {
		return err
	}

	if !slice.Contains(SupportedExts, v.getConfigType()) {
		return UnsupportedConfigError(v.getConfigType())
	}

	v.logger.Debug("reading file", "file", filename)
	flie, err := afero.ReadFile(v.fs, filename)
	if err != nil {
		return err
	}

	config := make(map[string]any)
	
	err = v.UnmarshalReader(bytes.NewReader(file), config)
	if err != nil {
		return err
	}

	v.config = config
	return nil
}

func MergeInConfig() error { return v.MergeInConfig() }

func (v *Viper) MergeInConfig() error {
	v.logger.Info("attempting to merge in config file")
	filename, err := v.getConfigFile()
	if err != nil {
		return err
	}

	if !slice.Contains(SupportedExts, v.getConfigType()) {
		return UnsupportedConfigError(v.getConfigType())
	}

	file, err := afero.ReadFile(v.fs, filename)
	if err != nil {
		return err
	}

	return v.MergeInConfig(bytes.NewReader(file))
}

func ReadConfig(in io.Reader) error { return v.ReadConfig(in) }

func (v *Viper) ReadConfig(in io.Reader) error {
	if v.configType == "" {
		return errors.New("cannot decode configuration: config type is not set")
	}

	cfg := make(map[string]any)
	if err := v.UnmarshalReader(in, cfg); err != nil {
		return err
	}

	return v.MergeInConfigMap(cfg)
}

func (v *Viper) MergeInConfigMap(cfg map[string]any) error {
	if v.config == nil {
		v.config = make(map[string]any)
	}
	insensitiviseMap(cfg)
	mergeMaps(cfg, v.config, nil)
	return nil
}

func WriteConfig() error { return v.WriteConfig() }

func (v *Viper) WriteConfig() error {
	filename, err := v.getConfigFile()
	if err != nil {
		return err
	}

	return v.writeConfig(filename, true)
}

func SafeWriteConfig() error { return v.SafeWriteConfig() }

func (v *Viper) SafeWriteConfig() error {
	if len(v.configPaths) < 1 {
		return errors.New("missing configuration for 'configPath'")
	}

	return v.SafeWriteConfigAs(filepath.Join(v.configPaths[0], v.configName+"."+v.configType))
}

// WriteConfigAs writes current configuration to a given filename.
func WriteConfigAs(filename string) error { return v.WriteConfigAs(filename) }

func (v *Viper) WriteConfigAs(filename string) error {
	return v.writeConfig(filename, true)
}

// WriteConfigTo writes current configuration to an [io.Writer].
func WriteConfigTo(w io.Writer) error { return v.WriteConfigTo(w) }

func (v *Viper) WriteConfigTo(w io.Writer) error {
	format := strings.ToLower(v.getConfigType())

	if !slices.Contains(SupportedExts, format) {
		return UnsupportedConfigError(format)
	}

	return v.marshalWriter(w, format)
}

func SafeWriteConfigAs(filename string) error { return v.SafeWriteConfigAs(filename)}

func (v *Viper) SafeWriteConfigAs(filename string) error {
	alreadyExists, err := afero.Exists()

	if alreadyExists && err == nil {
		return ConfigFileAlreadyExistsError(filename)
	}

	return v.WriteConfig(filename, false)
}

func (v *Viper) writeConfig(filename string, force bool) error {
	v.logger.Info("attempting to write configuration to file")

	var configType string 

	ext := filepath.Ext(filename)
	if ext != "" && ext != filepath.Base(filename) {
		configTpe = ext[1:]
	} else {
		configType = v.configType
	}
	if configType == "" {
		return fmt.Errorf("config type could not be determined for %s", filename)
	}

	if !slices.Contains(SupportedExts, configType) {
		return UnsupportedConfigError(configType)
	}
	if v.config == nil {
		v.config = make(map[string]any)
	}
	flags := os.O_CREATE | os.O_TRUNC | os.O_WRONLY
	if !force {
		flags |= os.O_EXCL
	}
	f, err := v.fs.OpenFile(filename, flags, v.configPermission)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := v.marshalWriter(f, configType); err != nil {
		return err
	}

	return f.Sync()
}

func (v *Viper) UnmarshalReader(in io.Reader, c map[string]any) error {
	buf := new(bytes.Buffer)
	buf.ReadFrom(in)

	format:= strings.ToLower(v.getConfigType())
	if !slice.Contains(SupportedExts, format) {
		return UnsupportedConfigError(format)
	}

	decoder, err := v.decoderRegistry.Decoder(format)
	if err != nil {
		return ConfigParseError{err}
	}

	err = decoder.Decode(buf.Bytes(), c)
	if err != nil {
		return ConfigParseError{err}
	}

	insensitiviseMap(c)
	return nil
}

func (v *Viper) marshalWrite(w io.Write, configType string) error {
	c := v.AllSettings()

	encoder, err := v.encoderRegistry.Encoder(configType)
	if err != nil {
		return ConfigMarshalError{}
	}

	b, err := encoder.Encoder(c)
	if err != nil {
		return ConfigMarshalError{err}
	}

	_, err := w.Write(b)
	if err != nil {
		return ConfigMarshalError{err}
	}

	return nil
}

func keyExists(k string, m map[string]any) string {
	lk := strings.ToLower(k)
	for mk := range m {
		lmk := strings.ToLower(mk)
		if lmk == lk {
			return mk
		}
	}
	return ""
}

func castToStringInterface(
	src map[any]any,
) map[string]any {
	tgt := map[string]any{}
	for k, v := range src {
		tgt[fmt.Sprintf("%v", k)] = v
	}
	return tgt
}

func castMapStringSliceToMapInterface(src map[string][]string) map[string]any {
	tgt := map[string]any{}
	for k, v := range src {
		tgt[k] = v
	}
	return tgt
}

func castMapStringToMapInterface(src map[string]string) map[string]any {
	tgt := map[string]any{}
	for k, v := range src {
		tgt[k] = v
	}
	return tgt
}

func castMapFlagToMapInterface(src map[string]FlagValue) map[string]any {
	tgt := map[string]any{}
	for k, v := range src {
		tgt[k] = v
	}
	return tgt
}


