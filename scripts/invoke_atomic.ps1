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
    [ValidateRange(1, 2147483647)]
    [int]$TestNumber
)

[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

try {
    if (-not (Test-Path -LiteralPath $ModulePath -PathType Leaf)) {
        throw "Module file not found: $ModulePath"
    }

    if (-not (Test-Path -LiteralPath $AtomicPath -PathType Container)) {
        throw "Atomic tests directory not found: $AtomicPath"
    }

    Import-Module -Name $ModulePath -ErrorAction Stop
    $null = Get-Command -Name "Invoke-AtomicTest" -ErrorAction Stop

    $techniqueDirectory = Join-Path -Path $AtomicPath $Technique
    $techniquePath = Join-Path -Path $techniqueDirectory "$Technique.yaml"

    if (-not (Test-Path -LiteralPath $techniquePath -PathType Leaf)) {
        throw "Technique definition not found: $techniquePath"
    }

    $definition = Get-AtomicTechnique `
        -Path $techniquePath `
        -ErrorAction Stop `
        -WarningAction SilentlyContinue `
        -WarningVariable definitionWarnings


    foreach ($warning in $definitionWarnings) {
        [Console]::Error.WriteLine("WARNING: {0}", $warning.Message)
    }

    if ($null -eq $definition) {
        throw "Could not read technique definition: $Technique"
    }

    $testCount = $definition.atomic_tests.Count

    if ($testCount -lt 1) {
        throw "Technique $Technique contains no tests"
    }

    if ($TestNumber -gt $testCount) {
        throw "test $TestNumber does not exist for $Technique. Available test numbers: 1-$testCount."
    }

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
        -TestNumbers $TestNumber `
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
            $_.'Test Number' -eq [string]$TestNumber -and
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

    $result = @{
        status         = "succeeded"
        run_id         = $runId
        technique      = $Technique
        test_number    = $TestNumber
        test_guid      = $testRun.GUID
        exit_code      = $testExitCode
        execution_log  = $executionLogPath
        diagnostic_log = $diagnosticLogPath
    }

    $resultJson = $result | ConvertTo-Json -Compress

    [Console]::Out.WriteLine($resultJson)
    [Console]::Error.WriteLine("Scenario execution succeeded")

    exit 0

}
catch {
    [Console]::Error.WriteLine("Scenario invocation failed: {0}",
        $_.Exception.Message)

    exit 1
}
