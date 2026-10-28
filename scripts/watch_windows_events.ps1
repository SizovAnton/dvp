param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$LogName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$StopFile
)

[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Send-EventNotification {
    param(
        [Parameter(Mandatory = $true)]
        $Notification
    )
    $record = $null

    try {
        $eventData = $Notification.SourceEventArgs
        $record = $eventData.EventRecord

        if ($null -ne $eventData.EventException) {
            throw $eventData.EventException
        }

        if ($null -eq $record) {
            throw "Notification contains no event record."
        }

        $message = @{
            type = "event"
            xml  = $record.ToXml()
        }

        $jsonLine = $message | ConvertTo-Json -Compress

        [Console]::Out.WriteLine($jsonLine)
        [Console]::Out.Flush()
    }
    finally {
        if ($null -ne $record) {
            $record.Dispose()
        }
        Remove-Event -EventIdentifier $Notification.EventIdentifier
    }
}

$sourceIdentifier = "DVP.WindowsEvents"
$registered = $false

$query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new($LogName,
    [System.Diagnostics.Eventing.Reader.PathType]::LogName, "*")

$watcher = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new(
    $query,
    $null,
    $false
)

try {
    if (Test-Path -LiteralPath $StopFile -ErrorAction Stop) {
        throw "Stop signal path already exists: $StopFile"
    }

    Register-ObjectEvent `
        -InputObject $watcher `
        -EventName "EventRecordWritten" `
        -SourceIdentifier $sourceIdentifier `
        -ErrorAction Stop

    $registered = $true
    $watcher.Enabled = $true

    $readMessage = @{
        type     = "ready"
        log_name = $LogName
    }

    $readyJson = $readMessage | ConvertTo-Json -Compress

    [Console]::Out.WriteLine($readyJson)
    [Console]::Out.Flush()
    Start-Sleep -Seconds 30
    $processed = 0

    while (-not (Test-Path -LiteralPath $StopFile -ErrorAction Stop)) {
        $notification = Wait-Event `
            -SourceIdentifier $sourceIdentifier `
            -Timeout 1

        if ($null -eq $notification) {
            continue
        }

        Send-EventNotification -Notification $notification
        $processed++
    }
    [Console]::Error.WriteLine("Stop signal received")

    $watcher.Enabled = $false
    $drained = 0
    
    do {
        $pending = @(
            Get-Event | 
            Where-Object { $_.SourceIdentifier -eq $sourceIdentifier }
        )

        foreach ($notification in $pending) {
            Send-EventNotification -Notification $notification
            $processed++
            $drained++
        }
    } while ($pending.Count -gt 0)

    [Console]::Error.WriteLine("Queued events forwarded: {0}", $drained)
    [Console]::Error.WriteLine("Total events forwarded: {0}", $processed)

}
catch {
    [Console]::Error.WriteLine(
        "Event collection failed: {0}",
        $_.Exception.Message)
    exit 1
}

finally {
    $watcher.Enabled = $false

    if ($registered) {
        Unregister-Event -SourceIdentifier $sourceIdentifier

        Get-Event -SourceIdentifier $sourceIdentifier -ErrorAction SilentlyContinue |
        ForEach-Object {
            $record = $_.SourceEventArgs.EventRecord

            if ($null -ne $record) {
                $record.Dispose()
            }

            Remove-Event -EventIdentifier $_.EventIdentifier
        }
    }

    $watcher.Dispose()
}

