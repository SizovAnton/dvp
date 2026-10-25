param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$LogName
)

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

    $notification = Wait-Event `
        -SourceIdentifier $sourceIdentifier `
        -Timeout 30

    if ($null -eq $notification) {
        Write-Output "No notification recived within 30 seconds."
    }
    else {
        $eventArgs = $notification.SourceEventArgs

        if ($null -ne $eventArgs.EventException) {
            throw $eventArgs.EventException
        }

        $record = $eventArgs.EventRecord

        if ($null -eq $record) {
            throw "Notification contains no event record."
        }
        Write-Output $record.ToXml()
    }

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

