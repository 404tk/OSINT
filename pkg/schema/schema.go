package schema

type Options map[string]string

// GetMetadata returns the value for a key if it exists.
func (o Options) GetMetadata(key string) (string, bool) {
	data, ok := o[key]
	if !ok || data == "" {
		return "", false
	}
	return data, true
}

func (o Options) CheckMetadata() Options {
	option := make(map[string]string)
	for k, v := range o {
		if v == "" {
			continue
		}
		option[k] = v
	}
	return option
}
