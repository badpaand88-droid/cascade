$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Push-Location $root
try {
  dotnet restore Cascade.Win/Cascade.Win.csproj -r win-x64
  if ($LASTEXITCODE -ne 0) { throw 'restore failed' }
  dotnet publish Cascade.Win/Cascade.Win.csproj -c Release -r win-x64 --no-restore -o publish/app
  if ($LASTEXITCODE -ne 0) { throw 'publish app failed' }
  New-Item -ItemType Directory -Force publish/app/Notices | Out-Null
  Copy-Item Notices/* publish/app/Notices/ -Force
  Copy-Item THIRD-PARTY.txt publish/app/ -Force
  if (Test-Path Assets/payload.zip) { Remove-Item Assets/payload.zip }
  Compress-Archive -Path publish/app/* -DestinationPath Assets/payload.zip
  [IO.File]::WriteAllText((Join-Path $root 'Assets/payload.sha256'), (Get-FileHash Assets/payload.zip -Algorithm SHA256).Hash.ToLowerInvariant())
  dotnet restore Cascade.Setup/Cascade.Setup.csproj -r win-x64
  if ($LASTEXITCODE -ne 0) { throw 'restore setup failed' }
  dotnet publish Cascade.Setup/Cascade.Setup.csproj -c Release -r win-x64 --no-restore -o publish/setup
  if ($LASTEXITCODE -ne 0) { throw 'publish setup failed' }
  Write-Host 'Ready: publish/setup/Cascade-Setup.exe'
} finally { Pop-Location }
