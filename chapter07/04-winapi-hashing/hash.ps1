$FunctionsToHash = @("CreateProcess")

$FunctionsToHash | ForEach-Object {
  $functionName = $_

  $hashValue = 0x35
  [int]$index = 0

  $functionName.ToCharArray() | ForEach-Object {
    $char = $_
    $charValue = [int64]$char
    $charValue = '0x{0:x}' -f $charValue
    $hashValue += $hashValue * 0xab10f29f + $charValue -band 0xffffff
    $hashHexValue = '0x{0:x}' -f $hashValue
    $index++
    Write-Host "Iteration $index : $char : $charValue : $hashHexValue"
  }
  Write-Host "$functionName`t $('0x00{0:x}' -f $hashValue)"
}
