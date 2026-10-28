param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ModulePath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AtomicPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Technique,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TestGuid

)

try {
    if (-not (Test-Path -LiteralPath $ModulePath -PathType Leaf)) {
        throw "Module file not found: $ModulePath"
    }

    if (-not (Test-Path -LiteralPath $AtomicPath -PathType Container)) {
        throw "Atomic tests directory not found: $AtomicPath"
    }

    Import-Module -Name $ModulePath -ErrorAction Stop
    $null = Get-Command -Name "Invoke-AtomicTest" -ErrorAction Stop

    $runId = [guid]::NewGuid().ToString()
    $runsRoot = Join-Path -Path $PSScriptRoot -ChildPath 'runs'
    $runDirectory = Join-Path -Path $runsRoot -ChildPath $runId

    $null = New-Item `
        -ItemType Directory `
        -Path $runDirectory `
        -Force `
        -ErrorAction Stop

    $executionLogPath = Join-Path $runDirectory 'execution.csv'
    $diagnosticLogPath = Join-Path $runDirectory 'diagnostic.log'

    [Console]::Error.WriteLine("Execution engine ready")
    $ProgressPreference = "SilentlyContinue"

    [Console]::Error.WriteLine("Running validation scenario")

    Invoke-AtomicTest `
        -AtomicTechnique $Technique `
        -TestGuids $TestGuid `
        -PathToAtomicsFolder $AtomicPath `
        -LoggingModule "Default-ExecutionLogger" `
        -ExecutionLogPath $executionLogPath `
        -ErrorAction Stop *> $diagnosticLogPath

    [Console]::Error.WriteLine("Run directory: {0}", $runDirectory)

    if (-not(Test-Path -LiteralPath $executionLogPath -PathType Leaf)) {
        throw "Execution log not found: $executionLogPath"
    }
    $rows = @(Import-Csv -LiteralPath $executionLogPath -ErrorAction Stop)

    $matchingRuns = @(
        $rows | Where-Object {
            $_.GUID -eq $TestGuid -and
            $_.Technique -eq $Technique
        }
    )

    if ($matchingRuns.Count -ne 1) {
        throw "Expected one matching execution record; found $($matchingRuns.Count)"
    }
    $testRun = $matchingRuns[0]
    $testExitCode = 0

    if (-not [int]::TryParse($testRun.ExitCode, [ref]$testExitCode)) {
        throw "Execution record contains an invalid ExitCode: '$($testRun.ExitCode)'"
    }

    if ($testExitCode -ne 0) {
        throw "Scenario execution failed with exit code $testExitCode"
    }
    [Console]::Error.WriteLine("Scenario execution succeeded")
    exit 0

}
catch {
    [Console]::Error.WriteLine("Scenario invocation failed: {0}",
        $_.Exception.Message)

    exit 1
}
