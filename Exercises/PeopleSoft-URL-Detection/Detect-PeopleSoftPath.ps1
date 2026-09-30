$events = @(
    [pscustomobject]@{
        Time = [datetime]"2026-09-29T10:00:00"
        Host = "WEB01"
        Type = "WebRequest"
        Path = "/%50SEMHUB/hub"
        ParentProcess = ""
        Process = ""
    },
    [pscustomobject]@{
        Time = [datetime]"2026-09-29T10:00:18"
        Host = "WEB01"
        Type = "ProcessStart"
        Path = ""
        ParentProcess = "java.exe"
        Process = "cmd.exe"
    },
    [pscustomobject]@{
        Time = [datetime]"2026-09-29T10:05:00"
        Host = "WEB02"
        Type = "WebRequest"
        Path = "/PSEMHUB/hub"
        ParentProcess = ""
        Process = ""
    }
)

$requests = foreach ($event in $events | Where-Object Type -eq "WebRequest") {
    $normalizedPath = [uri]::UnescapeDataString($event.Path)

    if ($normalizedPath -match '(?i)^/PSEMHUB/hub(?:/|$)') {
        [pscustomobject]@{
            Time = $event.Time
            Host = $event.Host
            RawPath = $event.Path
            NormalizedPath = $normalizedPath
        }
    }
}

foreach ($request in $requests) {
    $relatedShell = $events | Where-Object {
        $_.Type -eq "ProcessStart" -and
        $_.Host -eq $request.Host -and
        $_.Time -ge $request.Time -and
        $_.Time -le $request.Time.AddMinutes(2) -and
        $_.ParentProcess -match '(?i)^java(?:\.exe)?$' -and
        $_.Process -match '(?i)^(cmd\.exe|sh|bash)$'
    } | Select-Object -First 1

    [pscustomobject]@{
        Host = $request.Host
        RawPath = $request.RawPath
        NormalizedPath = $request.NormalizedPath
        Priority = if ($relatedShell) { "High - investigate process execution" }
                   else { "Lead - investigate request and exposure" }
        RelatedProcess = if ($relatedShell) {
            "$($relatedShell.ParentProcess) -> $($relatedShell.Process)"
        } else {
            "None observed"
        }
    }
}
