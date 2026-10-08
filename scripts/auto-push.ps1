param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectRoot
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
$logPath = Join-Path $ProjectRoot '.git\auto-push.log'
$createdNew = $false
$mutex = New-Object System.Threading.Mutex($true, 'Local\SentinelDICOMAutoPush', [ref]$createdNew)

if (-not $createdNew) { exit 0 }

function Write-Log([string]$Message) {
    Add-Content -LiteralPath $logPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $Message"
}

function Is-SourceChange([string]$Path) {
    $relative = [IO.Path]::GetRelativePath($ProjectRoot, $Path).Replace('\', '/')
    return -not ($relative -like '.git/*' -or $relative -like 'dicom_vault/*' -or $relative -like '__pycache__/*' -or $relative -like '.venv/*' -or $relative -like 'node_modules/*')
}

function Sync-Repository {
    Set-Location -LiteralPath $ProjectRoot
    & git add -A
    & git diff --cached --quiet
    if ($LASTEXITCODE -eq 0) { return }

    $message = "chore: auto-sync $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    & git commit -m $message *>> $logPath
    if ($LASTEXITCODE -ne 0) { Write-Log 'Commit failed; waiting for the next source change.'; return }

    & git pull --rebase origin main *>> $logPath
    if ($LASTEXITCODE -ne 0) { Write-Log 'Pull/rebase failed; resolve the conflict, then save a source file to retry.'; return }

    & git push origin main *>> $logPath
    if ($LASTEXITCODE -eq 0) { Write-Log 'Synced source changes to origin/main.' }
    else { Write-Log 'Push failed; verify GitHub credentials and remote access.' }
}

try {
    $watcher = New-Object IO.FileSystemWatcher $ProjectRoot, '*'
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true
    $events = @('Changed', 'Created', 'Deleted', 'Renamed') | ForEach-Object {
        Register-ObjectEvent -InputObject $watcher -EventName $_ -SourceIdentifier "autoPush$_"
    }
    $lastChange = Get-Date
    Sync-Repository

    while ($true) {
        $event = Wait-Event -Timeout 2
        if ($event) {
            $path = $event.SourceEventArgs.FullPath
            if (Is-SourceChange $path) { $lastChange = Get-Date }
            Remove-Event -EventIdentifier $event.EventIdentifier
        }
        if ($lastChange -and ((Get-Date) - $lastChange).TotalSeconds -ge 4) {
            Sync-Repository
            $lastChange = $null
        }
    }
}
finally {
    $events | ForEach-Object { Unregister-Event -SourceIdentifier $_.Name -ErrorAction SilentlyContinue }
    if ($watcher) { $watcher.Dispose() }
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
