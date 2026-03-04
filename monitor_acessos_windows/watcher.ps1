param(
  [Parameter(Mandatory=$false)][string]$LogName = 'Security',
  [Parameter(Mandatory=$true)][string]$XPathFilter,
  [switch]$IncludeMessage = $false,
  [int]$PollIntervalSeconds = 2
)

# ----- Modo 1: tentativa de assinatura (EventLogWatcher) -----
$xmlQuery = @"
<QueryList>
  <Query Id="0" Path="$LogName">
    <Select Path="$LogName">$XPathFilter</Select>
  </Query>
</QueryList>
"@

$EventingNS = 'System.Diagnostics.Eventing.Reader'
$usePollingFallback = $false
$elogWatcher = $null
$subscription = $null

try {
  $elogQuery   = New-Object "$EventingNS.EventLogQuery" ($LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xmlQuery)
  # readExistingEvents = $false (não tenta drenar histórico ao habilitar)
  $elogWatcher = New-Object "$EventingNS.EventLogWatcher" ($elogQuery, $null, $false)

  $action = {
    try {
      $rec = $Event.SourceEventArgs.EventRecord
      if ($null -eq $rec) { return }
      $xml = [xml]$rec.ToXml()

      $sys = $xml.Event.System
      $ed  = @{}
      foreach ($d in $xml.Event.EventData.Data) {
        $n = $d.Name
        if (-not $n) { continue }
        $ed[$n] = [string]$d.'#text'
      }

      $obj = [ordered]@{
        System = [ordered]@{
          Provider    = [string]$sys.Provider.Name
          EventID     = [string]$sys.EventID
          TimeCreated = [string]$sys.TimeCreated.SystemTime
          Computer    = [string]$sys.Computer
          Channel     = [string]$sys.Channel
          SecuritySid = [string]$sys.Security.UserID
        }
        EventData = $ed
      }

      if ($using:IncludeMessage.IsPresent) {
        try { $obj.Message = $rec.FormatDescription() } catch {}
      }

      $json = $obj | ConvertTo-Json -Compress -Depth 6
      [Console]::Out.WriteLine($json)
    }
    catch {
      [Console]::Error.WriteLine(("WatcherError: " + $_.Exception.Message))
    }
  }

  $subscription = Register-ObjectEvent -InputObject $elogWatcher -EventName EventRecordWritten -Action $action -ErrorAction Stop
  $elogWatcher.Enabled = $true
}
catch {
  [Console]::Error.WriteLine(("WatcherInfo: assinatura indisponível ({0}). Alternando para polling…" -f $_.Exception.Message))
  $usePollingFallback = $true
}

# ----- Modo 2: fallback por polling + bookmark simples -----
if ($usePollingFallback) {
  $lastRecordId = 0
  while ($true) {
    try {
      $events = Get-WinEvent -LogName $LogName -FilterXPath $XPathFilter -MaxEvents 50 -ErrorAction Stop
      foreach ($ev in $events) {
        if ($ev.RecordId -le $lastRecordId) { continue }

        $xml = [xml]$ev.ToXml()
        $sys = $xml.Event.System
        $ed  = @{}
        foreach ($d in $xml.Event.EventData.Data) {
          $n = $d.Name
          if (-not $n) { continue }
          $ed[$n] = [string]$d.'#text'
        }

        $obj = [ordered]@{
          System = [ordered]@{
            Provider    = [string]$sys.Provider.Name
            EventID     = [string]$sys.EventID
            TimeCreated = [string]$sys.TimeCreated.SystemTime
            Computer    = [string]$sys.Computer
            Channel     = [string]$sys.Channel
            SecuritySid = [string]$sys.Security.UserID
          }
          EventData = $ed
        }
        if ($IncludeMessage.IsPresent) { try { $obj.Message = $ev.FormatDescription() } catch {} }
        $json = $obj | ConvertTo-Json -Compress -Depth 6
        [Console]::Out.WriteLine($json)
        $lastRecordId = $ev.RecordId
      }
    }
    catch {
      [Console]::Error.WriteLine(("WatcherError: polling falhou: {0}" -f $_.Exception.Message))
    }
    Start-Sleep -Seconds $PollIntervalSeconds
  }
}
else {
  try { while ($true) { Start-Sleep -Seconds 1 } }
  finally {
    try { $elogWatcher.Enabled = $false } catch {}
    try { Unregister-Event -SourceIdentifier $subscription.Name -ErrorAction SilentlyContinue } catch {}
    try { $elogWatcher.Dispose() } catch {}
  }
}
