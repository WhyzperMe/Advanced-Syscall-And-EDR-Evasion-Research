# XOR String Encryptor for C++ Arrays
# Encrypts strings with XOR 0x5A and outputs C++ array format

function Encrypt-String {
    param(
        [string]$InputString,
        [byte]$Key = 0x5A
    )
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Original: '$InputString'" -ForegroundColor Green
    Write-Host "Key: 0x$($Key.ToString('X2'))" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($InputString)
    $bytesWithNull = $bytes + [byte]0x00
    
    $encrypted = @()
    foreach ($byte in $bytesWithNull) {
        $encrypted += ($byte -bxor $Key)
    }
    
    Write-Host "`nEncrypted bytes (C++ array format):" -ForegroundColor Yellow
    $varName = $InputString -replace '[^a-zA-Z0-9]', '_'
    Write-Host "unsigned char enc_$varName[] = {" -ForegroundColor White
    
    $line = "    "
    $count = 0
    foreach ($byte in $encrypted) {
        $line += "0x$($byte.ToString('X2')), "
        $count++
        if ($count % 12 -eq 0) {
            Write-Host $line -ForegroundColor White
            $line = "    "
        }
    }
    if ($line.Trim() -ne "") { Write-Host $line -ForegroundColor White }
    Write-Host "};" -ForegroundColor White
    
    return $encrypted
}

# Encrypt common strings
Encrypt-String "ntdll.dll"
Encrypt-String "kernel32.dll"
Encrypt-String "kernelbase.dll"
Encrypt-String "version.dll"
Encrypt-String "amsi.dll"
Encrypt-String "NtAllocateVirtualMemory"
Encrypt-String "NtWriteVirtualMemory"
Encrypt-String "NtProtectVirtualMemory"
Encrypt-String "NtQueueApcThread"
Encrypt-String "NtCreateThreadEx"
Encrypt-String "EtwEventWrite"