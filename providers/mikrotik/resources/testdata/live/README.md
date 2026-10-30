# Live RouterOS fixtures

Rows captured from a real MikroTik CHR device through the RouterOS API, in the
exact `map[string]string` shape an args builder is handed. See
`providers/mikrotik/TESTING.md` for how to refresh them.

Capture through the **API**, not the CLI: `/system/resource/print` pretty-prints
`1766.6MiB` where the API returns the raw `2113929216` the provider parses, so
CLI-derived fixtures would test the wrong thing.

## Secret-valued attributes are redacted

Every attribute RouterOS gates behind the `sensitive` policy — IPsec and RADIUS
`secret`, SNMPv3 `authentication-password` and `encryption-password` — is
replaced with the literal `REDACTED`. Keep it that way when refreshing.

The value must stay **non-empty**. `presenceField` reports whether the device
holds a secret without reading it, so it distinguishes present-and-non-empty
from absent; blanking these would change what the fixtures exercise.

Community and service *names* (`public`, `labpublic`) and enum values
(`yes-if-no-key`) are not secrets and are kept verbatim — they are meaningful
parser input.
