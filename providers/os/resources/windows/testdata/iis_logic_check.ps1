$ErrorActionPreference = 'Stop'

# Harness: loads the function definitions out of iis.ps1 (the real code, parsed
# from the shipped script) and runs them against mock Microsoft.Web.Administration
# shaped objects, so the conversion logic can be exercised off Windows.

$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'iis.ps1'
$errors = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) { throw "parse errors in iis.ps1" }

# Re-evaluate only the top-level variable assignments the functions depend on,
# plus the function definitions themselves.
foreach ($statement in $ast.EndBlock.Statements) {
  if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
    Invoke-Expression $statement.Extent.Text
    continue
  }
  if ($statement -is [System.Management.Automation.Language.AssignmentStatementAst]) {
    $name = $statement.Left.Extent.Text
    if ($name -in @('$sectionPaths', '$serverSectionPaths', '$collectionSections', '$redactedAttributes', '$logFormatNames')) {
      Invoke-Expression $statement.Extent.Text
    }
  }
}

function New-Attribute($name, $value) {
  [pscustomobject]@{ Name = $name; Value = $value }
}

# A configuration attribute the way Microsoft.Web.Administration really hands
# one over: `Value` is a boxed **Int32** even when the attribute is enum- or
# flags-typed, and the names live on the schema. Verified by reflection against
# Microsoft.Web.Administration 7.0.0.0 on a live IIS 10 — there is no
# GetFlagValues() on that assembly and no ConfigurationFlagValue type, so
# GetEnumValues() returns the members for both kinds and Schema.Type is the only
# thing that tells them apart.
function New-TypedAttribute($name, $value, $type, $members) {
  $schema = [pscustomobject]@{ Type = $type }
  $schema | Add-Member -MemberType ScriptMethod -Name GetEnumValues -Value {
    return $this._members
  }.GetNewClosure()
  $schema | Add-Member -MemberType NoteProperty -Name _members -Value @(
    $members | ForEach-Object { [pscustomobject]@{ Name = $_[0]; Value = [int64]$_[1] } })
  [pscustomobject]@{ Name = $name; Value = $value; Schema = $schema }
}

function New-Element($tag, $attributes, $children, $collection) {
  $element = [pscustomobject]@{
    ElementTagName = $tag
    Attributes     = $attributes
    ChildElements  = $children
    _collection    = $collection
  }
  $element | Add-Member -MemberType ScriptMethod -Name GetCollection -Value {
    if ($null -eq $this._collection) { throw "element has no default collection" }
    return $this._collection
  }
  return $element
}

$failures = 0
function Assert-Equal($expected, $actual, $label) {
  if ($expected -ne $actual) {
    Write-Host "FAIL $label : expected '$expected' got '$actual'"
    $script:failures++
  } else {
    Write-Host "ok   $label"
  }
}

# --- ConvertTo-PlainValue -----------------------------------------------------

Assert-Equal 1200 (ConvertTo-PlainValue ([System.TimeSpan]::FromMinutes(20))) 'TimeSpan 20m -> 1200 seconds'
Assert-Equal 0 (ConvertTo-PlainValue ([System.TimeSpan]::Zero)) 'TimeSpan zero -> 0'
Assert-Equal 104400 (ConvertTo-PlainValue ([System.TimeSpan]::FromMinutes(1740))) 'TimeSpan 29h -> 104400 seconds'
Assert-Equal 'Monday' (ConvertTo-PlainValue ([System.DayOfWeek]::Monday)) 'enum -> name'
Assert-Equal 'AABBCC' (ConvertTo-PlainValue ([byte[]]@(0xAA, 0xBB, 0xCC))) 'byte[] -> hex'
Assert-Equal '' (ConvertTo-PlainValue ([byte[]]@())) 'empty byte[] -> empty string'
Assert-Equal $true (ConvertTo-PlainValue $true) 'bool passthrough'
Assert-Equal 4096 (ConvertTo-PlainValue 4096) 'int passthrough'
Assert-Equal $null (ConvertTo-PlainValue $null) 'null passthrough'

# --- ConvertTo-PlainElement: attributes, redaction ---------------------------

$machineKey = New-Element 'machineKey' @(
  (New-Attribute 'validation' 'HMACSHA256'),
  (New-Attribute 'decryption' 'Auto'),
  (New-Attribute 'validationKey' 'AAAA1111BBBB2222'),
  (New-Attribute 'decryptionKey' 'CCCC3333DDDD4444')
) @() $null

$plain = ConvertTo-PlainElement $machineKey 3 $false
Assert-Equal 'HMACSHA256' $plain['validation'] 'machineKey validation kept'
Assert-Equal 'Auto' $plain['decryption'] 'machineKey decryption kept'
Assert-Equal $false ($plain.ContainsKey('validationKey')) 'validationKey redacted'
Assert-Equal $false ($plain.ContainsKey('decryptionKey')) 'decryptionKey redacted'

# --- nested child elements ----------------------------------------------------

$requestLimits = New-Element 'requestLimits' @(
  (New-Attribute 'maxAllowedContentLength' 30000000),
  (New-Attribute 'maxUrl' 4096),
  (New-Attribute 'maxQueryString' 2048)
) @() $null

$fileExtensions = New-Element 'fileExtensions' @(
  (New-Attribute 'allowUnlisted' $true)
) @() @(
  (New-Element 'add' @((New-Attribute 'fileExtension' '.config'), (New-Attribute 'allowed' $false)) @() $null)
)

$requestFiltering = New-Element 'requestFiltering' @(
  (New-Attribute 'allowDoubleEscaping' $false),
  (New-Attribute 'allowHighBitCharacters' $true),
  (New-Attribute 'removeServerHeader' $false)
) @($requestLimits, $fileExtensions) $null

$plain = ConvertTo-PlainElement $requestFiltering 3 $true
Assert-Equal 4096 $plain['requestLimits']['maxUrl'] 'nested requestLimits maxUrl'
Assert-Equal 30000000 $plain['requestLimits']['maxAllowedContentLength'] 'nested maxAllowedContentLength'
Assert-Equal $true $plain['fileExtensions']['allowUnlisted'] 'nested fileExtensions allowUnlisted'
Assert-Equal '.config' $plain['fileExtensions']['collection'][0]['fileExtension'] 'nested collection entry'
Assert-Equal 'add' $plain['fileExtensions']['collection'][0]['element'] 'collection entry tag name'

# collections are skipped entirely when the section is not on the allow list
$plain = ConvertTo-PlainElement $requestFiltering 3 $false
Assert-Equal $false ($plain['fileExtensions'].ContainsKey('collection')) 'collection omitted when not requested'

# --- depth cap ----------------------------------------------------------------

# depth N yields N levels of children below the element: the Nth level reports
# its attributes and the (N+1)th is dropped.
$deep5 = New-Element 'd5' @((New-Attribute 'leaf' 'too-deep')) @() $null
$deep4 = New-Element 'd4' @((New-Attribute 'leaf' 'v')) @($deep5) $null
$deep3 = New-Element 'd3' @() @($deep4) $null
$deep2 = New-Element 'd2' @() @($deep3) $null
$deep1 = New-Element 'd1' @() @($deep2) $null
$plain = ConvertTo-PlainElement $deep1 3 $false
Assert-Equal 'v' $plain['d2']['d3']['d4']['leaf'] 'third child level still reports attributes'
Assert-Equal $false ($plain['d2']['d3']['d4'].ContainsKey('d5')) 'recursion stops at the depth cap'

# The depth the script actually uses (5) has to reach
# system.applicationHost/sites -> siteDefaults -> ftpServer -> security -> ssl,
# which is four levels below the section element.
$ssl = New-Element 'ssl' @((New-Attribute 'controlChannelPolicy' 'SslRequire'), (New-Attribute 'dataChannelPolicy' 'SslRequire')) @() $null
$ftpSecurity = New-Element 'security' @() @($ssl) $null
$ftpServer = New-Element 'ftpServer' @() @($ftpSecurity) $null
$siteDefaults = New-Element 'siteDefaults' @() @($ftpServer) $null
$sitesSection = New-Element 'sites' @() @($siteDefaults) $null
$plain = ConvertTo-PlainElement $sitesSection 5 $false
Assert-Equal 'SslRequire' $plain['siteDefaults']['ftpServer']['security']['ssl']['controlChannelPolicy'] 'siteDefaults ftp ssl reached at depth 5'
$plain = ConvertTo-PlainElement $sitesSection 3 $false
Assert-Equal $false ($plain['siteDefaults']['ftpServer']['security'].ContainsKey('ssl')) 'depth 3 would have missed it'

# --- an element with no default collection must not blow up ------------------

$plain = ConvertTo-PlainElement $machineKey 3 $true
Assert-Equal 'HMACSHA256' $plain['validation'] 'GetCollection throw is tolerated'
Assert-Equal $false ($plain.ContainsKey('collection')) 'no collection key when the element has none'

# --- an element that reports its name only through the schema ----------------

$schemaNamed = [pscustomobject]@{
  ElementTagName = ''
  Attributes     = @((New-Attribute 'level' 'Full'))
  ChildElements  = @()
  Schema         = [pscustomobject]@{ Name = 'trust' }
}
$parent = New-Element 'parent' @() @($schemaNamed) $null
$plain = ConvertTo-PlainElement $parent 3 $false
Assert-Equal 'Full' $plain['trust']['level'] 'child named through Schema.Name'

# --- an element that reports no name at all is skipped, not fatal ------------

$unnamed = [pscustomobject]@{
  ElementTagName = ''
  Attributes     = @()
  ChildElements  = @()
  Schema         = $null
}
$parent = New-Element 'parent' @((New-Attribute 'keep' 'yes')) @($unnamed) $null
$plain = ConvertTo-PlainElement $parent 3 $false
Assert-Equal 'yes' $plain['keep'] 'unnamed child does not take the element down'
Assert-Equal 1 $plain.Count 'unnamed child is skipped'

# --- ConvertTo-AttributeValue: the defect this function exists for ------------
#
# Every one of these values is what a live IIS 10 actually reports, taken from a
# reflection probe on a stock Server 2022. Before the schema lookup they all
# came back as the bare number, formatted as a plausible-looking string.

# system.web/authentication/@mode on a stock server.
$authMode = New-TypedAttribute 'mode' 1 'enum' @(
  @('None', 0), @('Windows', 1), @('Passport', 2), @('Forms', 3), @('Federated', 4))
Assert-Equal $false ($authMode.Value -is [System.Enum]) 'the -is [System.Enum] test is false — this is the whole bug'
Assert-Equal 'Windows' (ConvertTo-AttributeValue $authMode) 'enum attribute resolves to its name'

# system.webServer/handlers/@accessPolicy. 513 is Read (1) + Script (512) and is
# not a member of the enum, so no lookup can name it.
$accessPolicy = New-TypedAttribute 'accessPolicy' 513 'flags' @(
  @('None', 0), @('Read', 1), @('Write', 2), @('Execute', 4), @('Source', 16),
  @('Script', 512), @('NoRemoteWrite', 1024), @('NoRemoteRead', 4096),
  @('NoRemoteExecute', 8192), @('NoRemoteScript', 16384))
Assert-Equal 'Read, Script' (ConvertTo-AttributeValue $accessPolicy) 'flags attribute decomposes to names'

$allSet = New-TypedAttribute 'accessPolicy' 7 'flags' @(
  @('None', 0), @('Read', 1), @('Write', 2), @('Execute', 4))
Assert-Equal 'Read, Write, Execute' (ConvertTo-AttributeValue $allSet) 'flags keep the schema order'

$noneSet = New-TypedAttribute 'accessPolicy' 0 'flags' @(@('None', 0), @('Read', 1))
Assert-Equal 'None' (ConvertTo-AttributeValue $noneSet) 'zero resolves to the zero-valued member'

# A bit the schema does not name is reported beside the ones it does, rather
# than dropped — silent loss is the failure this function exists to end.
$unknownBit = New-TypedAttribute 'accessPolicy' 65537 'flags' @(@('None', 0), @('Read', 1))
Assert-Equal 'Read, 65536' (ConvertTo-AttributeValue $unknownBit) 'an unnamed bit survives as a number'

# system.web/sessionState/@cookieless carries aliases for the same numbers —
# UseUri=0 and true=0, UseCookies=1 and false=1 — and the documented name comes
# first. A last-wins lookup would report `false` for a server using cookies.
$cookieless = New-TypedAttribute 'cookieless' 1 'enum' @(
  @('UseUri', 0), @('UseCookies', 1), @('AutoDetect', 2), @('UseDeviceProfile', 3),
  @('true', 0), @('false', 1))
Assert-Equal 'UseCookies' (ConvertTo-AttributeValue $cookieless) 'first match wins over a later alias'

# A number the schema does not name at all falls back rather than returning ''.
$unknownEnum = New-TypedAttribute 'mode' 99 'enum' @(@('None', 0), @('Windows', 1))
Assert-Equal 99 (ConvertTo-AttributeValue $unknownEnum) 'an unknown enum number is reported as itself'

# A plain attribute is untouched: strings, bools and numbers all still pass through.
Assert-Equal 'Full' (ConvertTo-AttributeValue (New-TypedAttribute 'level' 'Full' 'string' @())) 'string attribute untouched'
Assert-Equal $false (ConvertTo-AttributeValue (New-TypedAttribute 'debug' $false 'bool' @())) 'bool attribute untouched'
Assert-Equal 4096 (ConvertTo-AttributeValue (New-Attribute 'maxUrl' 4096)) 'attribute with no schema at all still works'

# ConvertTo-PlainElement has to route through it, or none of the above matters.
$handlers = New-Element 'handlers' @($accessPolicy) @() $null
$plain = ConvertTo-PlainElement $handlers 3 $false
Assert-Equal 'Read, Script' $plain['accessPolicy'] 'ConvertTo-PlainElement resolves attribute enums'

# --- ConvertTo-LogFormat ------------------------------------------------------
#
# The CLR member names are Iis, Ncsa, W3c and Custom, so ToString() gives "W3c".
# Everything a benchmark is written against says "W3C".
Assert-Equal 'W3C' (ConvertTo-LogFormat 'W3c') 'W3c -> W3C'
Assert-Equal 'NCSA' (ConvertTo-LogFormat 'Ncsa') 'Ncsa -> NCSA'
Assert-Equal 'IIS' (ConvertTo-LogFormat 'Iis') 'Iis -> IIS'
Assert-Equal 'Custom' (ConvertTo-LogFormat 'Custom') 'Custom is already right'
Assert-Equal 'Something' (ConvertTo-LogFormat 'Something') 'an unknown format passes through'

# --- Server-scope sections ----------------------------------------------------
#
# applicationPoolDefaults lives only in system.applicationHost/applicationPools.
# Without it in the list, the defaults every pool inherits are unreadable.
Assert-Equal $true ($serverSectionPaths -contains 'system.applicationHost/applicationPools') 'applicationPools is a server-scope section'
Assert-Equal $false ($collectionSections.ContainsKey('system.applicationHost/applicationPools')) 'pools stay out of the section; appPools reports them'

Write-Host ""
if ($failures -gt 0) {
  Write-Host "$failures FAILURES"
  exit 1
}
Write-Host "all harness assertions passed"
