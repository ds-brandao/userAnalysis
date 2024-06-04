function Get-CurrentLoggedInUser {
    $wmiQuery = "SELECT * FROM Win32_ComputerSystem"
    $computerSystem = Get-WmiObject -Query $wmiQuery
    $currentLoggedInUser = $computerSystem.UserName
    return $currentLoggedInUser
}

function Get-LoggedInUsers {
    $userRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $users = Get-ChildItem -Path $userRegPath | ForEach-Object {
        $sid = $_.PSChildName
        $profilePath = $_.GetValue('ProfileImagePath')
        $profileName = Split-Path -Path $profilePath -Leaf
        [PSCustomObject]@{
            SID = $sid
            DisplayName = $profileName
        }
    }
    return $users
}

function Get-UserProfileInfo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $profileRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$UserSID"
    $profileInfo = Get-ItemProperty -Path $profileRegPath
    [PSCustomObject]@{
        ProfilePath = $profileInfo.ProfileImagePath
        LastLoginTime = if ($profileInfo.PSObject.Properties['LastUseTime']) { $profileInfo.LastUseTime -as [datetime] } else { "N/A" }
        State = switch ($profileInfo.State) {
            0 { "Active" }
            256 { "Temporary" }
            512 { "Mandatory" }
            1024 { "Roaming" }
            2048 { "Other" }
            Default { "Unknown" }
        }
        EmailAddress = (Get-ItemProperty -Path "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\AccountPicture" -Name "UserEmailAddress" -ErrorAction SilentlyContinue).UserEmailAddress
        AccountPicture = (Get-ItemProperty -Path "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\AccountPicture" -Name "Image" -ErrorAction SilentlyContinue).Image
    }
}

function Get-UserLogonInfo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $userAccount = Get-WmiObject -Class Win32_UserAccount -Filter "SID='$UserSID'"
    [PSCustomObject]@{
        LastLogon = $userAccount.LastLogon
        LogonCount = $userAccount.LogonCount
        PasswordLastSet = $userAccount.PasswordLastSet
    }
}

function Get-UserNetworkConnections {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $networkRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
    $ssidPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged'
    $networks = Get-ChildItem -Path $networkRegPath | ForEach-Object {
        $profileGuid = $_.PSChildName
        $profilePath = Join-Path -Path $networkRegPath -ChildPath $profileGuid
        $userProfile = Get-ItemProperty -Path $profilePath
        $ssid = (Get-ItemProperty -Path "$ssidPath\$profileGuid" -ErrorAction SilentlyContinue).DefaultGatewayMac
        [PSCustomObject]@{
            ProfileName = $userProfile.ProfileName
            NetworkCategory = switch ($userProfile.Category) {
                0 { "Public" }
                1 { "Private" }
                2 { "Domain" }
                Default { "Unknown" }
            }
            Description = $userProfile.Description
            SSID = if ($ssid) { $ssid } else { "N/A" }
        }
    }
    return $networks
}

function Get-UserInstalledPrograms {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $uninstallRegPath = "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    $installedPrograms = Get-ChildItem -Path $uninstallRegPath -ErrorAction SilentlyContinue | ForEach-Object {
        $programName = $_.GetValue("DisplayName")
        $programVersion = $_.GetValue("DisplayVersion")
        if ($programName) {
            [PSCustomObject]@{
                Name = $programName
                Version = $programVersion
            }
        }
    }
    return $installedPrograms
}

function Get-UserRecentDocs {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $recentDocsRegPath = "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    $recentDocs = Get-ChildItem -Path $recentDocsRegPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Path = $_.PSPath
            Value = $_.GetValue("") -as [string]
        }
    }
    return $recentDocs
}

function Get-UserRecentFiles {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $recentFilesRegPath = "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
    $recentFiles = Get-ChildItem -Path $recentFilesRegPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Path = $_.PSPath
            Value = $_.GetValue("") -as [string]
        }
    }
    return $recentFiles
}

function Get-UserNetworkUsage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $networkAdapters = Get-NetAdapterStatistics
    $networkUsage = $networkAdapters | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            BytesSent = $_.BytesSent
            BytesReceived = $_.BytesReceived
        }
    }
    return $networkUsage
}

function Get-UserConnectedDevices {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $connectedDevices = Get-WmiObject -Class Win32_USBControllerDevice -Namespace root\cimv2 | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            Description = $_.Description
        }
    }
    return $connectedDevices
}

function Get-UserPrinterConnections {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $printerConnections = Get-WmiObject -Class Win32_Printer -Namespace root\cimv2 | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            PortName = $_.PortName
        }
    }
    return $printerConnections
}

function Get-UserScheduledTasks {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $scheduledTasks = Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq $UserSID } | ForEach-Object {
        [PSCustomObject]@{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
        }
    }
    return $scheduledTasks
}

function Get-UserInformation {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $userInfo = [PSCustomObject]@{
        ProfileInfo = Get-UserProfileInfo -UserSID $UserSID
        LogonInfo = Get-UserLogonInfo -UserSID $UserSID
        Networks = Get-UserNetworkConnections -UserSID $UserSID
        InstalledPrograms = Get-UserInstalledPrograms -UserSID $UserSID
        RecentDocs = Get-UserRecentDocs -UserSID $UserSID
        RecentFiles = Get-UserRecentFiles -UserSID $UserSID
        NetworkUsage = Get-UserNetworkUsage -UserSID $UserSID
        ConnectedDevices = Get-UserConnectedDevices -UserSID $UserSID
        PrinterConnections = Get-UserPrinterConnections -UserSID $UserSID
        ScheduledTasks = Get-UserScheduledTasks -UserSID $UserSID
    }
    return $userInfo
}

function Select-User {
    $currentLoggedInUser = Get-CurrentLoggedInUser
    $users = Get-LoggedInUsers
    $selectedUser = $users | Where-Object { $_.DisplayName -eq $currentLoggedInUser }

    if ($null -eq $selectedUser) {
        Write-Host "No users found or current user not found in registry."
        return
    }

    $userInfo = Get-UserInformation -UserSID $selectedUser.SID
    $userInfo | Format-List
}

# Exporting functions to module
Export-ModuleMember -Function Get-CurrentLoggedInUser, Get-LoggedInUsers, Get-UserProfileInfo, Get-UserLogonInfo, Get-UserNetworkConnections, Get-UserInstalledPrograms, Get-UserRecentDocs, Get-UserRecentFiles, Get-UserNetworkUsage, Get-UserConnectedDevices, Get-UserPrinterConnections, Get-UserScheduledTasks, Get-UserInformation, Select-User