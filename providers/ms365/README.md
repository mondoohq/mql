# ms365 Provider

## Prerequisites

- A registered Azure AD app configured with certificate-based authentication
  - The certificate needs to be in (RSA) format
  - The certificate should to be stored in a pem format
- PowerShell

__NOTE__

At the moment some of the resources within this provider require the use of PowerShell. Please ensure `pwsh` is in your PATH. For example, `pwsh -c 'Get-Date'` should return a timestamp.

The resources that still need PowerShell are `ms365.exchangeonline`, `ms365.sharepointonline`, `ms365.teams` and `microsoft.security.exchange`. Everything else, including `microsoft.powerbi`, is served directly from the REST APIs and works without `pwsh`.

Also it's recommended that you use certificate based authentication with this provider, especially with the resources that need to use powershell, this is due to the way those cmdlets authenticate.  Certificate auth is more reliable when testing.

### Mac
```shell
brew install --cask powershell
```
### Linux
Please refer to the [documentation](https://learn.microsoft.com/en-us/powershell/scripting/install/linux-overview) based on your distribution.

## Authentication
You will need to provide your app's client and tenant id as well certificate.
```
export MS365_CLIENT_ID='your-client-id'
export MS365_TENANT_ID='your-tenant-id'
export MS365_CERTIFICATE_PATH='certificate.combo.pem'
```
```shell
mql shell ms365 --certificate-path ${MS365_CERTIFICATE_PATH} --tenant-id ${MS365_TENANT_ID} --client-id ${MS365_CLIENT_ID}
```

## Examples
### List Directory Names

`microsoft.domains`

Example output
```
microsoft.domains: [
  0: microsoft.domain id="azuremondoo.onmicrosoft.com"
]
```

### Get Information about the Azure Application Your Using

Get the integration thumbprint

```shell
MS365_THUMBPRINT=$(mql run local -c "parse.certificates('${MS365_CERTIFICATE_PATH}') { fingerprints.sha1 }" --json | jq -r '.[0]["parse.certificates.list"][0]["fingerprints[sha1]"]')
```

Use it to find the Azure Entra Application

```shell
mql run ms365 --certificate-path ${MS365_CERTIFICATE_PATH} --tenant-id ${MS365_TENANT_ID} --client-id ${MS365_CLIENT_ID} -c "microsoft.applications.where(appId=='${MS365_CLIENT_ID}').where(certificates.any(thumbprint == /${MS365_THUMBPRINT}/i)) { name certificates }"
```

## Troubleshooting

### Convert pfx to pem
Extract the private key
```shell
openssl pkcs12 -in certificate.pfx -nocerts -out privatekey.key -nodes
```
Extract the certificate
```shell
openssl pkcs12 -in certificate.pfx -clcerts -nokeys -out certificate.pem
```
Combine certs
```shell
cat privatekey.key certificate.pem > certificate.combo.pem
```

### Insufficient Privileges

```
x unable to create runtime for asset error="rpc error: code = Unknown desc = authentication failed: Insufficient privileges to complete the operation." asset=
FTL could not find an asset that we can connect to
```
This is a catch all so start with double check your application permissions, for example does the application have Global Reader?


### Unknown digest
```
pkcs12: unknown digest algorithm: 2.16.840.1.101.3.4.2.1"
```
Your certificate is probably in PFX format instead of PEM.
