param(
    [string]$Configuration = "Release",
    [string]$SshKeyPath = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$projDir = Join-Path $repoRoot "MiniClassIsland.ExtendManagement"
$outDir = Join-Path $projDir "bin\$Configuration\net8.0"
$distDir = Join-Path $repoRoot "dist"
$stageDir = Join-Path $distDir "_stage"
$cipxPath = Join-Path $distDir "org.miniopensource.miniclassisland.extendmanagement.cipx"

# 1. 自动解析 GitHub 提交使用的 SSH 签名密钥
if ([string]::IsNullOrWhiteSpace($SshKeyPath)) {
    $gitSigningKey = (git config --global --get user.signingkey 2>$null)
    if (-not [string]::IsNullOrWhiteSpace($gitSigningKey)) {
        $SshKeyPath = $gitSigningKey.Trim()
    } else {
        $SshKeyPath = Join-Path $env:USERPROFILE ".ssh\id_ed25519"
    }
}

# 如果配置的是 .pub，转换为对应私钥路径用于 ssh-keygen -Y sign
if ($SshKeyPath.EndsWith(".pub", [System.StringComparison]::OrdinalIgnoreCase)) {
    $privCandidate = $SshKeyPath.Substring(0, $SshKeyPath.Length - 4)
    if (Test-Path $privCandidate) {
        $pubKeyPath = $SshKeyPath
        $privKeyPath = $privCandidate
    } else {
        $pubKeyPath = $SshKeyPath
        $privKeyPath = $SshKeyPath
    }
} else {
    $privKeyPath = $SshKeyPath
    $pubKeyPath = "$SshKeyPath.pub"
}

if (-not (Test-Path $privKeyPath)) {
    throw "未找到 SSH 私钥文件: $privKeyPath"
}
if (-not (Test-Path $pubKeyPath)) {
    throw "未找到 SSH 公钥文件: $pubKeyPath"
}

$pubKeyLine = (Get-Content $pubKeyPath -Raw).Trim()

# 2. 编译 Release
Write-Host "[1/5] 正在构建 Release 产物..." -ForegroundColor Cyan
dotnet build (Join-Path $repoRoot "MiniClassIsland.ExtendManagement.sln") -c $Configuration --nologo

# 3. 准备打包暂存目录
Write-Host "[2/5] 正在归集插件核心文件..." -ForegroundColor Cyan
if (Test-Path $stageDir) { Remove-Item -Recurse -Force $stageDir }
New-Item -ItemType Directory -Path $stageDir | Out-Null
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

$coreFiles = @(
    "MiniClassIsland.ExtendManagement.dll",
    "MiniClassIsland.ExtendManagement.deps.json",
    "manifest.yml",
    "icon.png",
    "README.md"
)

foreach ($file in $coreFiles) {
    $src = Join-Path $outDir $file
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $stageDir $file) -Force
    }
}

# 从 manifest.yml 提取版本号
$manifestYml = Get-Content (Join-Path $stageDir "manifest.yml") -Raw
$version = "2.0.0.1"
if ($manifestYml -match '(?m)^version:\s*["'']?([^"''\r\n]+)["'']?') {
    $version = $Matches[1].Trim()
}

# 4. 生成确定性 SIGNATURE.json 并调用 ssh-keygen -Y sign 生成 SIGNATURE.sshsig
Write-Host "[3/5] 正在生成文件 SHA-256 清单并使用 GitHub SSH 密钥 ($privKeyPath) 签名..." -ForegroundColor Cyan
$fileHashes = [ordered]@{}
Get-ChildItem $stageDir -File | Sort-Object Name | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $fileHashes[$_.Name] = $hash
}

$sigManifestObj = [ordered]@{
    schema          = "miniclassisland.cipx.manifest.v1"
    pluginId        = "org.miniopensource.miniclassisland.extendmanagement"
    version         = $version
    signerPublicKey = $pubKeyLine
    signedAtUtc     = [DateTimeOffset]::UtcNow.ToString("o")
    files           = $fileHashes
}

$sigManifestJson = $sigManifestObj | ConvertTo-Json -Depth 5
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$sigManifestPath = Join-Path $stageDir "SIGNATURE.json"
[System.IO.File]::WriteAllText($sigManifestPath, $sigManifestJson, $utf8NoBom)

# 调用 OpenSSH ssh-keygen -Y sign
$namespace = "miniclassisland.cipx.v1"
& ssh-keygen -Y sign -f $privKeyPath -n $namespace $sigManifestPath | Out-Null
$generatedSigPath = "$sigManifestPath.sig"
$targetSshSigPath = Join-Path $stageDir "SIGNATURE.sshsig"
if (-not (Test-Path $generatedSigPath)) {
    throw "ssh-keygen -Y sign 未生成签名文件: $generatedSigPath"
}
Move-Item $generatedSigPath $targetSshSigPath -Force

# 使用 ssh-keygen -Y verify 自检验证（使用 cmd /c "< file" 重定向原始字节，避免 PowerShell 管道附加换行符）
$allowedSignersPath = Join-Path $distDir "_allowed_signers.tmp"
$principal = ($pubKeyLine -split '\s+')[2]
if ([string]::IsNullOrWhiteSpace($principal)) { $principal = "signer" }
[System.IO.File]::WriteAllText($allowedSignersPath, "$principal namespaces=""$namespace"" $pubKeyLine`n", $utf8NoBom)
$verifyOutput = cmd /c "ssh-keygen -Y verify -f ""$allowedSignersPath"" -I ""$principal"" -n ""$namespace"" -s ""$targetSshSigPath"" < ""$sigManifestPath"" 2>&1"
$verifyExitCode = $LASTEXITCODE
Remove-Item $allowedSignersPath -Force -ErrorAction SilentlyContinue
if ($verifyExitCode -ne 0) {
    throw "OpenSSH 签名自检失败: $verifyOutput"
}
Write-Host "  OpenSSH 验签自检: $verifyOutput" -ForegroundColor Green

# 5. 创建 .cipx 并写入 ZIP Central Directory Comment 尾部双保险签名块
Write-Host "[4/5] 正在封装 .cipx 并注入 ZIP 尾部自包含签名注释块..." -ForegroundColor Cyan
if (Test-Path $cipxPath) { Remove-Item -Force $cipxPath }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($stageDir, $cipxPath)

$manifestBytes = [System.IO.File]::ReadAllBytes($sigManifestPath)
$sshSigText = [System.IO.File]::ReadAllText($targetSshSigPath, $utf8NoBom)
$commentEnvelope = [ordered]@{
    manifest = [Convert]::ToBase64String($manifestBytes)
    sshsig   = $sshSigText
} | ConvertTo-Json -Compress
$commentString = "MCI-SSHSIG-V1:" + [Convert]::ToBase64String($utf8NoBom.GetBytes($commentEnvelope))
$commentBytes = $utf8NoBom.GetBytes($commentString)

# 修改 ZIP EOCD (End of Central Directory) 注释长度与内容
$zipBytes = [System.IO.File]::ReadAllBytes($cipxPath)
$eocdPos = -1
for ($i = $zipBytes.Length - 22; $i -ge [Math]::Max(0, $zipBytes.Length - 65557); $i--) {
    if ($zipBytes[$i] -eq 0x50 -and $zipBytes[$i+1] -eq 0x4B -and $zipBytes[$i+2] -eq 0x05 -and $zipBytes[$i+3] -eq 0x06) {
        $eocdPos = $i
        break
    }
}
if ($eocdPos -ge 0 -and $commentBytes.Length -le 65535) {
    $ms = New-Object System.IO.MemoryStream
    $ms.Write($zipBytes, 0, $eocdPos + 20)
    $lenBytes = [BitConverter]::GetBytes([uint16]$commentBytes.Length)
    $ms.Write($lenBytes, 0, 2)
    $ms.Write($commentBytes, 0, $commentBytes.Length)
    [System.IO.File]::WriteAllBytes($cipxPath, $ms.ToArray())
    $ms.Dispose()
}

# 对整包生成外部 detached 签名 (.cipx.sshsig) 供分发渠道校验
& ssh-keygen -Y sign -f $privKeyPath -n $namespace $cipxPath | Out-Null
if (Test-Path "$cipxPath.sig") {
    Move-Item "$cipxPath.sig" "$cipxPath.sshsig" -Force
}

Remove-Item -Recurse -Force $stageDir

# 6. 输出哈希校验文件并同步带版本号的归档包
Write-Host "[5/5] 正在生成 MD5 与 SHA-256 校验文件..." -ForegroundColor Cyan
$versionedCipxPath = Join-Path $distDir "org.miniopensource.miniclassisland.extendmanagement-$version.cipx"
Copy-Item $cipxPath $versionedCipxPath -Force
$md5 = (Get-FileHash $cipxPath -Algorithm MD5).Hash.ToLowerInvariant()
$sha256 = (Get-FileHash $cipxPath -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText("$cipxPath.md5", $md5, $utf8NoBom)
[System.IO.File]::WriteAllText("$cipxPath.sha256", $sha256, $utf8NoBom)

Write-Host "=====================================================" -ForegroundColor Green
Write-Host "已成功签名并打包: $cipxPath" -ForegroundColor Green
Write-Host "  签名密钥 : $pubKeyLine"
Write-Host "  MD5      : $md5"
Write-Host "  SHA-256  : $sha256"
Write-Host "=====================================================" -ForegroundColor Green
