package viper

type FlagValueSet interface {
}

type FlagValue interface {
	HasChanged() bool
	Name() string
	ValueString() string
	ValueType() string
}
