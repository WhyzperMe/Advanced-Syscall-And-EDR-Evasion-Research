# Shellcode Extractor + XOR Encryptor
# Extracts .text section from MASM .obj files

param(
    [Parameter(Mandatory=$true)]
    [string]$ObjFile,
    [byte]$XorKey = 0x5A,
    [switch]$Encrypt
)

if (-not (Test-Path $ObjFile)) {
    Write-Host "[-] File not found: $ObjFile" -ForegroundColor Red
    exit 1
}

$data = [System.IO.File]::ReadAllBytes($ObjFile)
$numSections = [BitConverter]::ToUInt16($data, 2)
$sizeOptHeader = [BitConverter]::ToUInt16($data, 16)
$sectionOffset = 20 + $sizeOptHeader

$shellcode = $null
$foundSection = $null

for ($i = 0; $i -lt $numSections; $i++) {
    $secStart = $sectionOffset + ($i * 40)
    $nameBytes = $data[$secStart..($secStart + 7)]
    $name = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)
    $sizeOfRawData = [BitConverter]::ToUInt32($data, $secStart + 16)
    $pointerToRawData = [BitConverter]::ToUInt32($data, $secStart + 20)
    
    if ($name -like '.text*' -or $name -eq 'CODE') {
        if ($sizeOfRawData -gt 0) {
            if ($null -eq $shellcode -or $sizeOfRawData -gt $shellcode.Length) {
                $shellcode = $data[$pointerToRawData..($pointerToRawData + $sizeOfRawData - 1)]
                $foundSection = $name
            }
        }
    }
}

if ($null -eq $shellcode) {
    Write-Host "[-] Could not find .text* or CODE section!" -ForegroundColor Red
    exit 1
}

if ($Encrypt) {
    for ($i = 0; $i -lt $shellcode.Length; $i++) {
        $shellcode[$i] = $shellcode[$i] -bxor $XorKey
    }
}

Write-Host "unsigned char shellcode[] = {" -ForegroundColor White
$line = "    "
$count = 0
foreach ($byte in $shellcode) {
    $line += "0x$($byte.ToString('X2')), "
    $count++
    if ($count % 12 -eq 0) { Write-Host $line; $line = "    " }
}
if ($line.Trim() -ne "") { Write-Host $line }
Write-Host "};"