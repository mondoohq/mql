// Shared library exporting a type and a function, imported under aliases.

@export()
type sku = 'Standard_LRS' | 'Premium_LRS'

@export()
type tier = 'hot' | 'cool' | 'archive'

@export()
func buildName(prefix string, suffix string) string => '${prefix}-${suffix}'
