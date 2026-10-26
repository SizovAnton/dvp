param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$LogName
)

[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

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
    Register-ObjectEvent `
        -InputObject $watcher `
        -EventName "EventRecordWritten" `
        -SourceIdentifier $sourceIdentifier `
        -ErrorAction Stop

    $registered = $true
    $watcher.Enabled = $true

    [Console]::Error.WriteLine("Collector ready")

    $processed = 0

    while ($processed -lt 3) {
        $notification = Wait-Event `
            -SourceIdentifier $sourceIdentifier `
            -Timeout 30

        if ($null -eq $notification) {
            [Console]::Error.WriteLine("No notification received within 30 seconds")
            break
        }
        $record = $null

        try {
            $eventData = $notification.SourceEventArgs
            $record = $eventData.EventRecord

            if ($null -ne $eventData.EventException) {
                throw $eventData.EventException
            }

            if ($null -eq $record) {
                throw "Notification contains no event record."
            }

            $message = @{
                xml = $record.ToXml()
            }

            $jsonLine = $message | ConvertTo-Json -Compress

            [Console]::Out.WriteLine($jsonLine)
            [Console]::Out.Flush()

            $processed++
        }
        finally {
            if ($null -ne $record) {
                $record.Dispose()
            }

            Remove-Event -EventIdentifier $notification.EventIdentifier
        }
    }

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

