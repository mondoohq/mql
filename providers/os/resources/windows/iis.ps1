# Copyright Mondoo, Inc. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1

$ErrorActionPreference = 'Stop'

$inetsrv = Join-Path $env:windir 'system32\inetsrv'
$appHostPath = Join-Path $inetsrv 'config\applicationHost.config'
$mwaDll = Join-Path $inetsrv 'Microsoft.Web.Administration.dll'

# IIS is present only when the shared configuration file and the management
# assembly are both on disk. The assembly ships with the web server core, so it
# is a stronger signal than the WebAdministration module, which needs the
# separate management-scripting feature and is absent on a minimal install.
if (-not (Test-Path $appHostPath) -or -not (Test-Path $mwaDll)) {
  ConvertTo-Json @{ installed = $false; version = ''; applicationHostPath = ''; sites = @(); appPools = @(); config = $null } -Depth 12 -Compress
  exit 0
}

[void][System.Reflection.Assembly]::LoadFrom($mwaDll)

# InetStp\VersionString reads "Version 10.0" on IIS 10, not "10.0" — verified on
# a live Server 2022. Reported unstripped it makes every version comparison a
# string match against a prefix nobody expects, so the prefix comes off here.
$version = ''
try {
  $version = [string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction Stop).VersionString
  $version = ($version -replace '^\s*Version\s+', '').Trim()
} catch {
  $version = ''
}

# Sections resolved for every configuration scope. Each is read through the
# server manager, so the reported value is the effective one, after the
# machine.config, root web.config, applicationHost.config, location, site
# web.config and application web.config chain has been applied.
$sectionPaths = @(
  'system.web/authentication',
  'system.web/authorization',
  'system.web/compilation',
  'system.web/customErrors',
  'system.web/deployment',
  'system.web/httpCookies',
  'system.web/httpRuntime',
  'system.web/machineKey',
  'system.web/pages',
  'system.web/sessionState',
  'system.web/trace',
  'system.web/trust',
  'system.webServer/asp',
  'system.webServer/directoryBrowse',
  'system.webServer/handlers',
  'system.webServer/httpErrors',
  'system.webServer/httpLogging',
  'system.webServer/httpProtocol',
  'system.webServer/httpRedirect',
  'system.webServer/isapiFilters',
  'system.webServer/proxy',
  'system.webServer/security/access',
  'system.webServer/security/authentication/anonymousAuthentication',
  'system.webServer/security/authentication/basicAuthentication',
  'system.webServer/security/authentication/clientCertificateMappingAuthentication',
  'system.webServer/security/authentication/digestAuthentication',
  'system.webServer/security/authentication/iisClientCertificateMappingAuthentication',
  'system.webServer/security/authentication/windowsAuthentication',
  'system.webServer/security/authorization',
  'system.webServer/security/dynamicIpSecurity',
  'system.webServer/security/ipSecurity',
  'system.webServer/security/isapiCgiRestriction',
  'system.webServer/security/requestFiltering',
  'system.webServer/staticContent',
  'system.webServer/urlCompression'
)

# Sections read only at server scope: they configure the server or the defaults
# a new site or application pool inherits, and are not resolvable per site.
# applicationPools reports applicationPoolDefaults; the pools themselves are
# appPools, so its collection stays out.
$serverSectionPaths = @(
  'system.applicationHost/applicationPools',
  'system.applicationHost/sites',
  'system.applicationHost/log',
  'system.ftpServer/security/authentication'
)

# Sections whose collection members carry the setting rather than the element
# attributes: a handler mapping, a MIME map, a denied file extension. Everything
# else reports attributes and named child elements only, which keeps large
# inherited collections out of every scope's payload.
$collectionSections = @{
  'system.webServer/handlers'                     = $true
  'system.webServer/httpProtocol'                 = $true
  'system.webServer/isapiFilters'                 = $true
  'system.webServer/security/authorization'       = $true
  'system.webServer/security/ipSecurity'          = $true
  'system.webServer/security/isapiCgiRestriction' = $true
  'system.webServer/security/requestFiltering'    = $true
  'system.webServer/staticContent'                = $true
  'system.web/authorization'                      = $true
  'system.web/authentication'                     = $true
}

# Attributes that carry key material rather than configuration. machineKey's
# validationKey and decryptionKey are symmetric secrets and a virtual directory
# or application pool identity may carry a password; reporting any of them would
# put a credential into every scan result.
$redactedAttributes = @{
  'validationKey' = $true
  'decryptionKey' = $true
  'password'      = $true
}

function ConvertTo-PlainValue($v) {
  if ($null -eq $v) { return $null }
  if ($v -is [System.TimeSpan]) { return [int64]$v.TotalSeconds }
  # Reached by the typed MWA properties below (Site.State, SiteLogFile.LogFormat
  # and the rest), which really are enum instances. It is NOT reached by a
  # configuration *attribute*: ConfigurationAttribute.Value boxes an Int32 even
  # when the attribute is enum- or flags-typed, so this test is false for all of
  # them and they used to fall through to the numeric branch below and report a
  # bare number. See ConvertTo-AttributeValue.
  if ($v -is [System.Enum]) { return $v.ToString() }
  if ($v -is [byte[]]) {
    if ($v.Length -eq 0) { return '' }
    return ([System.BitConverter]::ToString($v) -replace '-', '')
  }
  if ($v -is [bool] -or $v -is [string]) { return $v }
  if ($v -is [int] -or $v -is [int64] -or $v -is [uint32] -or $v -is [uint64] -or $v -is [double]) { return $v }
  return $v.ToString()
}

# A configuration element reports its tag through ElementTagName; the schema
# name is the fallback for the few elements that leave it empty. Neither is
# called Name, and indexing a hashtable with the null that Name returns throws
# under the Stop preference set above, which would drop the whole section.
function Get-ElementName($element) {
  $name = ''
  try { $name = [string]$element.ElementTagName } catch { $name = '' }
  if (-not [string]::IsNullOrEmpty($name)) { return $name }
  try { $name = [string]$element.Schema.Name } catch { $name = '' }
  return $name
}

# Resolve a configuration attribute to the value a reader expects, using its
# schema to turn an enum or flags number into the label it stands for.
#
# This exists because `ConfigurationAttribute.Value` boxes an **Int32** for
# enum- and flags-typed attributes rather than an enum instance. The obvious
# `-is [System.Enum]` test is therefore false for every one of them, and the
# number falls through to the numeric branch and is reported as-is — so
# `system.web/authentication/@mode` read back as `1` and formatted as the
# string "1", which looks like a value rather than like a bug. Verified by
# reflection on IIS 10 (Microsoft.Web.Administration 7.0.0.0): every one of the
# ten typed enum fields, and the untyped ones, report `System.Int32`.
#
# `ConfigurationAttributeSchema.GetEnumValues()` returns the members for
# **both** kinds. There is no `GetFlagValues()` on this assembly and no
# `ConfigurationFlagValue` type — `Schema.Type` ("enum" or "flags") is the only
# thing that distinguishes them, and it is what decides between a lookup and a
# bit decomposition here.
# The LogFormat enum's CLR member names are Iis, Ncsa, W3c and Custom — verified
# by reflection on IIS 10 — so ToString() gives "W3c". IIS Manager, appcmd, the
# logFile/@logFormat attribute and every benchmark that names a log format all
# write "W3C". Reporting the CLR casing makes `logFormat == "W3C"` false on a
# server that is in fact logging W3C, which is the direction that matters.
$logFormatNames = @{
  'Iis'    = 'IIS'
  'Ncsa'   = 'NCSA'
  'W3c'    = 'W3C'
  'Custom' = 'Custom'
}

function ConvertTo-LogFormat($value) {
  $name = ConvertTo-PlainValue $value
  if ($name -is [string] -and $logFormatNames.ContainsKey($name)) { return $logFormatNames[$name] }
  return $name
}

function ConvertTo-AttributeValue($attribute) {
  $v = $attribute.Value
  if ($null -eq $v) { return $null }

  $type = ''
  $members = $null
  try {
    $schema = $attribute.Schema
    if ($null -ne $schema) {
      $type = [string]$schema.Type
      if ($type -eq 'enum' -or $type -eq 'flags') { $members = @($schema.GetEnumValues()) }
    }
  } catch {
    $members = $null
  }
  if ($null -eq $members -or $members.Count -eq 0) { return ConvertTo-PlainValue $v }

  $number = $null
  try { $number = [int64]$v } catch { return ConvertTo-PlainValue $v }

  if ($type -eq 'enum') {
    # First match, not last. Some schemas carry aliases for the same number —
    # system.web/sessionState/@cookieless lists UseUri=0 and true=0, and
    # UseCookies=1 and false=1 — and the documented name is the one that comes
    # first. A last-wins lookup reports `true` where IIS Manager shows UseUri.
    foreach ($member in $members) {
      if ([int64]$member.Value -eq $number) { return [string]$member.Name }
    }
    return ConvertTo-PlainValue $v
  }

  # Flags. Decomposed rather than looked up: a flags attribute holds a bitwise
  # OR of its members and its value is usually not one of them. The one that
  # motivates this is system.webServer/handlers/@accessPolicy, whose default is
  # 513 — Read (1) plus Script (512) — and which no lookup can name.
  if ($number -eq 0) {
    foreach ($member in $members) {
      if ([int64]$member.Value -eq 0) { return [string]$member.Name }
    }
    return ''
  }
  $names = @()
  $remaining = $number
  foreach ($member in $members) {
    $bit = [int64]$member.Value
    if ($bit -eq 0) { continue }
    if (($number -band $bit) -eq $bit) {
      $names += [string]$member.Name
      $remaining = $remaining -band (-bnot $bit)
    }
  }
  # A bit the schema does not name is reported as a number beside the names it
  # does. Dropping it would be the same silent loss this function exists to fix.
  if ($remaining -ne 0) { $names += [string]$remaining }
  # Comma-space, which is how .NET renders a flags enum and therefore how the
  # typed MWA properties in this script already read.
  return ($names -join ', ')
}

function ConvertTo-PlainElement($element, $depth, $withCollection) {
  $out = @{}
  foreach ($attribute in $element.Attributes) {
    if ($redactedAttributes.ContainsKey($attribute.Name)) { continue }
    $out[$attribute.Name] = ConvertTo-AttributeValue $attribute
  }

  if ($depth -le 0) { return $out }

  foreach ($child in $element.ChildElements) {
    $childName = Get-ElementName $child
    if ([string]::IsNullOrEmpty($childName)) { continue }
    $out[$childName] = ConvertTo-PlainElement $child ($depth - 1) $withCollection
  }

  if ($withCollection) {
    $collection = $null
    try { $collection = $element.GetCollection() } catch { $collection = $null }
    if ($null -ne $collection) {
      $items = @()
      foreach ($item in $collection) {
        $entry = ConvertTo-PlainElement $item ($depth - 1) $withCollection
        $entry['element'] = Get-ElementName $item
        $items += , $entry
      }
      $out['collection'] = @($items)
    }
  }

  return $out
}

function Get-SectionMap($configuration, $paths) {
  $sections = @{}
  foreach ($sectionPath in $paths) {
    $section = $null
    try {
      $section = $configuration.GetSection($sectionPath)
    } catch {
      continue
    }
    if ($null -eq $section) { continue }
    $withCollection = $collectionSections.ContainsKey($sectionPath)
    try {
      $sections[$sectionPath] = ConvertTo-PlainElement $section 5 $withCollection
    } catch {
      continue
    }
  }
  return $sections
}

function Get-ScopeConfiguration($manager, $siteName, $virtualPath) {
  $configuration = $null
  try {
    $configuration = $manager.GetWebConfiguration($siteName, $virtualPath)
  } catch {
    return @{}
  }
  return Get-SectionMap $configuration $sectionPaths
}

$manager = New-Object Microsoft.Web.Administration.ServerManager

$appPools = @()
foreach ($pool in $manager.ApplicationPools) {
  $state = ''
  try { $state = $pool.State.ToString() } catch { $state = '' }

  $schedule = @()
  try {
    foreach ($entry in $pool.Recycling.PeriodicRestart.Schedule) {
      $schedule += , ([int64](ConvertTo-PlainValue $entry.Time))
    }
  } catch {
    $schedule = @()
  }

  $appPools += , @{
    name                           = $pool.Name
    state                          = $state
    autoStart                      = $pool.AutoStart
    startMode                      = (ConvertTo-PlainValue $pool.StartMode)
    managedRuntimeVersion          = $pool.ManagedRuntimeVersion
    managedPipelineMode            = (ConvertTo-PlainValue $pool.ManagedPipelineMode)
    enable32BitAppOnWin64          = $pool.Enable32BitAppOnWin64
    queueLength                    = $pool.QueueLength
    identityType                   = (ConvertTo-PlainValue $pool.ProcessModel.IdentityType)
    userName                       = $pool.ProcessModel.UserName
    idleTimeout                    = (ConvertTo-PlainValue $pool.ProcessModel.IdleTimeout)
    maxProcesses                   = $pool.ProcessModel.MaxProcesses
    pingingEnabled                 = $pool.ProcessModel.PingingEnabled
    loadUserProfile                = $pool.ProcessModel.LoadUserProfile
    periodicRestartTime            = (ConvertTo-PlainValue $pool.Recycling.PeriodicRestart.Time)
    periodicRestartRequests        = $pool.Recycling.PeriodicRestart.Requests
    periodicRestartPrivateMemory   = $pool.Recycling.PeriodicRestart.PrivateMemory
    periodicRestartMemory          = $pool.Recycling.PeriodicRestart.Memory
    periodicRestartSchedule        = @($schedule)
    logEventOnRecycle              = (ConvertTo-PlainValue $pool.Recycling.LogEventOnRecycle)
    disallowRotationOnConfigChange = $pool.Recycling.DisallowRotationOnConfigChange
    disallowOverlappingRotation    = $pool.Recycling.DisallowOverlappingRotation
    rapidFailProtection            = $pool.Failure.RapidFailProtection
    rapidFailProtectionInterval    = (ConvertTo-PlainValue $pool.Failure.RapidFailProtectionInterval)
    rapidFailProtectionMaxCrashes  = $pool.Failure.RapidFailProtectionMaxCrashes
  }
}

$sites = @()
foreach ($site in $manager.Sites) {
  $siteState = ''
  try { $siteState = $site.State.ToString() } catch { $siteState = '' }

  $bindings = @()
  foreach ($binding in $site.Bindings) {
    $port = 0
    $address = ''
    try {
      if ($null -ne $binding.EndPoint) {
        $port = [int]$binding.EndPoint.Port
        if ($null -ne $binding.EndPoint.Address) { $address = $binding.EndPoint.Address.ToString() }
      }
    } catch {
      $port = 0
    }

    $certificateHash = ''
    try { $certificateHash = [string](ConvertTo-PlainValue $binding.CertificateHash) } catch { $certificateHash = '' }

    $certificateStore = ''
    try { $certificateStore = [string]$binding.CertificateStoreName } catch { $certificateStore = '' }

    $sslFlags = 0
    try { $sslFlags = [int]$binding.SslFlags } catch { $sslFlags = 0 }

    $hostName = ''
    try { $hostName = [string]$binding.Host } catch { $hostName = '' }

    $bindings += , @{
      protocol             = $binding.Protocol
      bindingInformation   = $binding.BindingInformation
      hostName             = $hostName
      port                 = $port
      ipAddress            = $address
      certificateHash      = $certificateHash
      certificateStoreName = $certificateStore
      sslFlags             = $sslFlags
    }
  }

  $rootPath = ''
  $rootPool = ''
  $applications = @()
  foreach ($application in $site.Applications) {
    $virtualDirectories = @()
    $applicationRoot = ''
    foreach ($directory in $application.VirtualDirectories) {
      if ($directory.Path -eq '/') { $applicationRoot = $directory.PhysicalPath }
      $virtualDirectories += , @{
        path         = $directory.Path
        physicalPath = $directory.PhysicalPath
        userName     = $directory.UserName
        logonMethod  = (ConvertTo-PlainValue $directory.LogonMethod)
      }
    }

    if ($application.Path -eq '/') {
      $rootPath = $applicationRoot
      $rootPool = $application.ApplicationPoolName
    }

    # The root application resolves to the same scope as the site itself, so its
    # configuration is left out here and the site's is reused for it.
    $applicationConfig = $null
    if ($application.Path -ne '/') {
      $applicationConfig = Get-ScopeConfiguration $manager $site.Name $application.Path
    }

    $applications += , @{
      path               = $application.Path
      physicalPath       = $applicationRoot
      applicationPool    = $application.ApplicationPoolName
      enabledProtocols   = $application.EnabledProtocols
      virtualDirectories = @($virtualDirectories)
      config             = $applicationConfig
    }
  }

  $logEnabled = $true
  try { $logEnabled = ($site.LogFile.Enabled -ne $false) } catch { $logEnabled = $true }

  $logTarget = ''
  try { $logTarget = [string](ConvertTo-PlainValue $site.LogFile.LogTargetW3C) } catch { $logTarget = '' }

  $hsts = $null
  try {
    $hstsElement = $site.GetChildElement('hsts')
    if ($null -ne $hstsElement) { $hsts = ConvertTo-PlainElement $hstsElement 1 $false }
  } catch {
    $hsts = $null
  }

  $sites += , @{
    id                   = [int64]$site.Id
    name                 = $site.Name
    state                = $siteState
    physicalPath         = $rootPath
    applicationPool      = $rootPool
    serverAutoStart      = $site.ServerAutoStart
    logEnabled           = $logEnabled
    logDirectory         = $site.LogFile.Directory
    logFormat            = (ConvertTo-LogFormat $site.LogFile.LogFormat)
    logPeriod            = (ConvertTo-PlainValue $site.LogFile.Period)
    logTruncateSize      = $site.LogFile.TruncateSize
    logFields            = (ConvertTo-PlainValue $site.LogFile.LogExtFileFlags)
    logTarget            = $logTarget
    logLocalTimeRollover = $site.LogFile.LocalTimeRollover
    hsts                 = $hsts
    bindings             = @($bindings)
    applications         = @($applications)
    config               = Get-ScopeConfiguration $manager $site.Name '/'
  }
}

$serverConfig = @{}
try {
  $appHostConfiguration = $manager.GetApplicationHostConfiguration()
  $serverConfig = Get-SectionMap $appHostConfiguration ($sectionPaths + $serverSectionPaths)
} catch {
  $serverConfig = @{}
}

ConvertTo-Json @{
  installed = $true
  version   = $version
  applicationHostPath = $appHostPath
  sites     = @($sites)
  appPools  = @($appPools)
  config    = $serverConfig
} -Depth 12 -Compress
