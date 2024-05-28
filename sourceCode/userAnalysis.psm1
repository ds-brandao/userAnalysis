function Get-UserProfileInfo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $profileRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$UserSID"
    $profileInfo = Get-ItemProperty -Path $profileRegPath
    [PSCustomObject]@{
        ProfilePath = $profileInfo.ProfileImagePath
        LastLoginTime = $profileInfo.LastUseTime
        State = $profileInfo.State
    }
}

function Get-UserNetworkConnections {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $networkRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
    $networks = Get-ChildItem -Path $networkRegPath | ForEach-Object {
        $profileGuid = $_.PSChildName
        $profilePath = Join-Path -Path $networkRegPath -ChildPath $profileGuid
        $userProfile = Get-ItemProperty -Path $profilePath
        [PSCustomObject]@{
            ProfileName = $userProfile.ProfileName
            NetworkCategory = $userProfile.Category
            Description = $userProfile.Description
        }
    }
    return $networks
}

function Get-UserSoftwareSettings {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $softwareRegPath = "HKU:\$UserSID\Software"
    $softwareSettings = Get-ChildItem -Path $softwareRegPath -Recurse | ForEach-Object {
        [PSCustomObject]@{
            Path = $_.PSPath
            Value = $_.GetValue("")
        }
    }
    return $softwareSettings
}

function Get-UserRecentDocs {
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserSID
    )
    $recentDocsRegPath = "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    $recentDocs = Get-ChildItem -Path $recentDocsRegPath -Recurse | ForEach-Object {
        [PSCustomObject]@{
            Path = $_.PSPath
            Value = $_.GetValue("")
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
        SoftwareSettings = Get-UserSoftwareSettings -UserSID $UserSID
        RecentDocs = Get-UserRecentDocs -UserSID $UserSID
    }
    return $userInfo
}

function Select-User {
    $users = Get-LoggedInUsers
    $selectedUser = $users | Out-GridView -Title "Select a User" -PassThru
    if ($null -ne $selectedUser) {
        $userInfo = Get-UserInformation -UserSID $selectedUser.SID
        $userInfo | Format-List
    } else {
        Write-Host "No user selected."
    }
}

# Exporting functions to module
Export-ModuleMember -Function Get-LoggedInUsers, Get-UserProfileInfo, Get-UserNetworkConnections, Get-UserSoftwareSettings, Get-UserRecentDocs, Get-UserInformation, Select-User

