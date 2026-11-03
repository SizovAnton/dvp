param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$LogNamesJson,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$StopFile,

    [ValidateRange(0, 60)]
    [int]$PostRunWaitSeconds = 3
)

[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

try {
    $wrappedJson = '{"channels":' + $LogNamesJson + '}'

    $parsedObject = ConvertFrom-Json `
        -InputObject $wrappedJson `
        -ErrorAction Stop
    
    $parsedLogNames = $parsedObject.channels

    if ($parsedLogNames -isnot [System.Array]) {
        throw "LogNamesJson must contain a JSON array."
    }

    if ($parsedLogNames.Count -eq 0){
        throw "At least one event channel is required."
    }

    $seenLogNames = @{}

    $logNames = @(
        foreach ($name in $parsedLogNames){
            if ($name -isnot [string]){
                throw "Each event channel must be a string"
            }

            $name = $name.Trim()

            if([string]::IsNullOrWhiteSpace($name)){
                throw "Event channel must not be empty."
            }

            if($seenLogNames.ContainsKey($name)){
                throw "Duplicate event channel: $name"
            }

            $seenLogNames[$name] = $true
            $name
        }
    )
    
}
catch{
    [Console]::Error.WriteLine(
        "Invalid collector channels: {0}",
        $_.Exception.Message
    )
    exit 1
}

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

$subscriptions = [System.Collections.Generic.List[object]]::new()

$sourceIdentifiers = @{}

try {
    if (Test-Path -LiteralPath $StopFile -ErrorAction Stop) {
        throw "Stop signal path already exists: $StopFile"
    }

    foreach ($logName in $logNames) {
        try {
            $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
                $logName,
                [System.Diagnostics.Eventing.Reader.PathType]::LogName,
                "*"
            )

            $watcher = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new(
                $query,
                $null,
                $false
            )

            $sourceIdentifier = "DVP.WindowsEvents.$([guid]::NewGuid())"

            $subscription = [PSCustomObject]@{
                LogName          = $logName
                SourceIdentifier = $sourceIdentifier
                Watcher          = $watcher
                Registered       = $false
            }

            $subscriptions.Add($subscription)
            $sourceIdentifiers[$sourceIdentifier] = $logName

            Register-ObjectEvent `
                -InputObject $watcher `
                -EventName "EventRecordWritten" `
                -SourceIdentifier $sourceIdentifier `
                -ErrorAction Stop

            $subscription.Registered = $true
            $watcher.Enabled = $true
        }
        catch {
            throw "Cannot start channel [$logName]: $($_.Exception.Message)"
        }
    }

    $readyMessage = @{
        type     = "ready"
        channels = @($logNames)
    }

    $readyJson = $readyMessage | ConvertTo-Json -Compress
    [Console]::Out.WriteLine($readyJson)
    [Console]::Out.Flush()

    $processed = 0

    $postRunTimer = $null

    while ($true) {
        If ($null -eq $postRunTimer) {
            if (Test-Path -LiteralPath $StopFile -ErrorAction Stop) {
                $postRunTimer = [System.Diagnostics.Stopwatch]::StartNew()

                [Console]::Error.WriteLine(
                    "Stop requested; post-run wait: {0} seconds",
                    $PostRunWaitSeconds
                )
            }
        }

        if ($null -ne $postRunTimer) {
            if ($postRunTimer.Elapsed.TotalSeconds -ge $PostRunWaitSeconds) {
                break
            }
        }

        $pending = @(
            Get-Event |
            Where-Object {
                $sourceIdentifiers.ContainsKey($_.SourceIdentifier)
            }
        )

        if ($pending.Count -eq 0){
            Start-Sleep -Milliseconds 100
            continue
        }
        foreach($notification in $pending){
            try{
                Send-EventNotification -Notification $notification
                $processed++
            }
            catch{
                $channel = $sourceIdentifiers[$notification.SourceIdentifier]
                throw "Collection failed for [$channel]: $($_.Exception.Message)"
            }
        }
    }

    [Console]::Error.WriteLine(
        "Post-run observation finished; elapsed: {0:F2} seconds",
        $postRunTimer.Elapsed.TotalSeconds
    )

    foreach ($subscription in $subscriptions){
        $subscription.Watcher.Enabled = $false
    }

    $drained = 0

    do {
        $pending = @(
            Get-Event |
            Where-Object { $sourceIdentifiers.ContainsKey($_.SourceIdentifier)}
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
    $cleanupFailed = $false

    foreach ($subscription in $subscriptions) {
        try {
            $subscription.Watcher.Enabled = $false
        }
        catch {
            $cleanupFailed = $true
            [Console]::Error.WriteLine(
                "Cannot disable watcher [{0}]: {1}",
                $subscription.LogName,
                $_.Exception.Message
            )
        }

        try {
            if ($subscription.Registered) {
                Unregister-Event `
                    -SourceIdentifier $subscription.SourceIdentifier `
                    -ErrorAction Stop
            }
        }
        catch {
            $cleanupFailed = $true
            [Console]::Error.WriteLine(
                "Cannot unregister [{0}]: {1}",
                $subscription.LogName,
                $_.Exception.Message
            )
        }

        $pending = @(
            Get-Event `
                -SourceIdentifier $subscription.SourceIdentifier `
                -ErrorAction SilentlyContinue
        )

        foreach ($notification in $pending) {
            try {
                $record = $notification.SourceEventArgs.EventRecord

                if ($null -ne $record) {
                    $record.Dispose()
                }
            }
            catch {
                $cleanupFailed = $true
                [Console]::Error.WriteLine(
                    "Cannot dispose queued record [{0}]: {1}",
                    $subscription.LogName,
                    $_.Exception.Message
                )
            }
            finally {
                try {
                    Remove-Event `
                        -EventIdentifier $notification.EventIdentifier `
                        -ErrorAction Stop
                }
                catch {
                    $cleanupFailed = $true
                    [Console]::Error.WriteLine(
                        "Cannot remove queued notification [{0}]: {1}",
                        $subscription.LogName,
                        $_.Exception.Message
                    )
                }
            }
        }

        try {
            $subscription.Watcher.Dispose()
        }
        catch {
            $cleanupFailed = $true
            [Console]::Error.WriteLine(
                "Cannot dispose watcher [{0}]: {1}",
                $subscription.LogName,
                $_.Exception.Message
            )
        }
    }

    if ($cleanupFailed) {
        exit 1
    }
}

