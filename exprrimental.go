package viper

func ExprimentalBindStruct() Option {
	return optionFunc(func(v *Viper) {
		v.experimentalBindStruct = true
	})
}
