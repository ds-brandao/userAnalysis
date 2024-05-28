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

function Get-UserSoftwareSettings {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    # Mount HKU if not already mounted
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    }

    $softwareRegPath = "HKU:\$UserSID\Software"
    $softwareSettings = Get-ChildItem -Path $softwareRegPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Path = $_.PSPath
            Value = $_.GetValue("") -as [string]
        }
    }
    return $softwareSettings
}

function Get-UserRecentDocs {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    # Mount HKU if not already mounted
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    }

    $recentDocsRegPath = "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    $recentDocs = Get-ChildItem -Path $recentDocsRegPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            Path = $_.PSPath
            Value = $_.GetValue("") -as [string]
        }
    }
    return $recentDocs
}

function Get-UserInformation {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $userInfo = [PSCustomObject]@{
        ProfileInfo = Get-UserProfileInfo -UserSID $UserSID
        Networks = Get-UserNetworkConnections -UserSID $UserSID
        # SoftwareSettings and RecentDocs are large, so summarized here
        SoftwareSettings = "Software settings found under HKU:\$UserSID\Software"
        RecentDocs = "Recent documents found under HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    }
    return $userInfo
}

function Select-User {
    $users = Get-LoggedInUsers
    if ($users.Count -eq 0) {
        Write-Host "No users found."
        return
    }

    Write-Host "Select a User:"
    for ($i = 0; $i -lt $users.Count; $i++) {
        Write-Host "$($i + 1). $($users[$i].DisplayName)"
    }

    $selection = Read-Host "Enter the number of the user you want to select"
    if ($selection -match '^\d+$' -and $selection -ge 1 -and $selection -le $users.Count) {
        $selectedUser = $users[$selection - 1]
        $userInfo = Get-UserInformation -UserSID $selectedUser.SID
        $userInfo | Format-List
    } else {
        Write-Host "Invalid selection. No user selected."
    }
}

# Exporting functions to module
Export-ModuleMember -Function Get-LoggedInUsers, Get-UserProfileInfo, Get-UserNetworkConnections, Get-UserSoftwareSettings, Get-UserRecentDocs, Get-UserInformation, Select-User