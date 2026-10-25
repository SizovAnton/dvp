param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$LogName
)

try {
    $event = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop

    $xml = $event.ToXml()
    Write-Output $xml
}
catch {
    [Console]::Error.WriteLine(
    "Failed to read event log '{0}': {1}",
    $LogName,
    $_.Exception.Message
)
    exit 1
}