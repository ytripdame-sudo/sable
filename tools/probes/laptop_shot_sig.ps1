$ns = 'root\virtualization\v2'
$svc = Get-CimClass -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
$svc.CimClassMethods['GetVirtualSystemThumbnailImage'] | ForEach-Object {
    "method : " + $_.Name
    $_.Parameters | ForEach-Object { "  {0,-14} {1}" -f $_.Name, $_.CimType }
}
