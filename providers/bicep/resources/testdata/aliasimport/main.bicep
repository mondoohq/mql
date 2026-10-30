// Aliased named import: the imported symbol is renamed in this file, but the
// symbol it pulls from the target is still `sku` / `buildName`.
import { sku as skuAlias, buildName as makeName } from './shared.bicep'

param location string = 'westeurope'
