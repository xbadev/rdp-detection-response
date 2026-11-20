# Pester 5 unit tests for Lib\RdpDetection.psm1 (pure logic + state files).
# Run: Invoke-Pester -Path .\tests
# Nothing here touches the real Security log or firewall: those calls are mocked.

BeforeAll {
    $env:RDP_LAB_CONFIG = Join-Path $PSScriptRoot '..\lab.config.psd1'
    Import-Module (Join-Path $PSScriptRoot '..\Lib\RdpDetection.psm1') -Force

    function New-Rec {
        param([string]$Ip, [string]$User, [int]$SecondsAgo = 0)
        [pscustomobject]@{
            TimeCreated = (Get-Date).AddSeconds(-$SecondsAgo)
            IpAddress   = $Ip
            TargetUser  = $User
            LogonType   = '3'
            Status      = '0xC000006D'
            SubStatus   = '0xC000006A'
            Workstation = ''
        }
    }
}

Describe 'Test-IsPrivateOrLocalIp' {
    It 'treats <Ip> as private=<Expected>' -ForEach @(
        @{ Ip = '10.10.10.30';  Expected = $true }
        @{ Ip = '192.168.1.5';  Expected = $true }
        @{ Ip = '172.16.0.1';   Expected = $true }
        @{ Ip = '172.31.255.1'; Expected = $true }
        @{ Ip = '172.32.0.1';   Expected = $false }
        @{ Ip = '169.254.10.1'; Expected = $true }
        @{ Ip = 'fe80::1';      Expected = $true }
        @{ Ip = '8.8.8.8';      Expected = $false }
        @{ Ip = '203.0.113.7';  Expected = $false }
    ) {
        Test-IsPrivateOrLocalIp -Ip $Ip | Should -Be $Expected
    }
}

Describe 'Find-BruteForceBursts' {
    It 'accepts an empty record list without throwing' {
        { @(Find-BruteForceBursts -Records @() -Threshold 5) } | Should -Not -Throw
        @(Find-BruteForceBursts -Records @() -Threshold 5).Count | Should -Be 0
    }

    It 'does not flag a pair below the threshold' {
        $r = 1..4 | ForEach-Object { New-Rec '10.10.10.30' 'labuser' $_ }
        @(Find-BruteForceBursts -Records @($r) -Threshold 5).Count | Should -Be 0
    }

    It 'flags a pair at the threshold with the right fields' {
        $r = 1..5 | ForEach-Object { New-Rec '10.10.10.30' 'labuser' $_ }
        $hits = @(Find-BruteForceBursts -Records @($r) -Threshold 5)
        $hits.Count         | Should -Be 1
        $hits[0].SourceIp   | Should -Be '10.10.10.30'
        $hits[0].TargetUser | Should -Be 'labuser'
        $hits[0].Count      | Should -Be 5
        $hits[0].FirstSeen  | Should -BeLessThan $hits[0].LastSeen
    }

    It 'handles a single record (no scalar-unrolling crash)' {
        $one = New-Rec '10.10.10.30' 'labuser'
        @(Find-BruteForceBursts -Records @($one) -Threshold 1).Count | Should -Be 1
    }

    It 'counts per (IP, user): 3 + 3 against two users does not reach 5' {
        $r = @(1..3 | ForEach-Object { New-Rec '10.10.10.30' 'alice' $_ }) +
             @(1..3 | ForEach-Object { New-Rec '10.10.10.30' 'bob' $_ })
        @(Find-BruteForceBursts -Records $r -Threshold 5).Count | Should -Be 0
    }

    It 'reports the larger burst first' {
        $r = @(1..5 | ForEach-Object { New-Rec '10.10.10.30' 'labuser' $_ }) +
             @(1..7 | ForEach-Object { New-Rec '10.10.10.99' 'labuser' $_ })
        $hits = @(Find-BruteForceBursts -Records $r -Threshold 5)
        $hits.Count       | Should -Be 2
        $hits[0].SourceIp | Should -Be '10.10.10.99'
    }
}

Describe 'Banlist persistence' {
    BeforeEach { $path = Join-Path $TestDrive 'banlist.json' }

    It 'round-trips an empty list as a JSON array' {
        Save-LabBanList -List @() -Path $path
        (Get-Content $path -Raw).Trim() | Should -Be '[]'
        @(Read-LabBanList -Path $path).Count | Should -Be 0
    }

    It 'round-trips one entry as an array, not a bare object' {
        $entry = [pscustomobject]@{ ip = '10.10.10.30'; user = 'labuser'; count = 5
                                    firstSeen = '2026-01-01T12:00:00'; lastSeen = '2026-01-01T12:00:05'
                                    expiresAt = '2099-01-01T00:00:00' }
        Save-LabBanList -List @($entry) -Path $path
        (Get-Content $path -Raw).Trim() | Should -BeLike '`[*`]'
        $back = @(Read-LabBanList -Path $path)
        $back.Count    | Should -Be 1
        $back[0].ip    | Should -Be '10.10.10.30'
    }

    It 'round-trips several entries' {
        $list = 1..3 | ForEach-Object {
            [pscustomobject]@{ ip = "10.10.10.$_"; user = 'u'; count = 5; firstSeen = ''; lastSeen = ''
                               expiresAt = '2099-01-01T00:00:00' } }
        Save-LabBanList -List @($list) -Path $path
        @(Read-LabBanList -Path $path).Count | Should -Be 3
    }

    It 'reads a missing file as empty' {
        @(Read-LabBanList -Path (Join-Path $TestDrive 'nope.json')).Count | Should -Be 0
    }
}

Describe 'Remove-ExpiredBans' {
    BeforeAll {
        Mock -ModuleName RdpDetection Unblock-LabIp { $null }
        Mock -ModuleName RdpDetection Write-LabLog { $null }
    }

    It 'accepts an empty banlist without throwing' {
        { @(Remove-ExpiredBans -BanList @()) } | Should -Not -Throw
        @(Remove-ExpiredBans -BanList @()).Count | Should -Be 0
    }

    It 'keeps active bans and unblocks expired ones' {
        $active  = [pscustomobject]@{ ip = '10.10.10.30'; expiresAt = (Get-Date).AddMinutes(10).ToString('s') }
        $expired = [pscustomobject]@{ ip = '10.10.10.99'; expiresAt = (Get-Date).AddMinutes(-1).ToString('s') }
        $kept = @(Remove-ExpiredBans -BanList @($active, $expired))
        $kept.Count    | Should -Be 1
        $kept[0].ip    | Should -Be '10.10.10.30'
        Should -Invoke -ModuleName RdpDetection Unblock-LabIp -Times 1 -Exactly -ParameterFilter { $Ip -eq '10.10.10.99' }
    }
}

Describe 'Alert cooldown' {
    BeforeAll {
        Mock -ModuleName RdpDetection Write-LabLog { $null }
        Mock -ModuleName RdpDetection Import-LabConfig {
            @{ AlertCooldownPath = (Join-Path $env:RDP_TEST_DIR 'cooldowns.json'); AlertCooldownMinutes = 10 }
        }
    }
    BeforeEach { $env:RDP_TEST_DIR = $TestDrive }

    It 'is not in cooldown before any alert' {
        Test-LabAlertCooldown -Key '10.10.10.30' | Should -BeFalse
    }

    It 'is in cooldown right after an alert, per IP' {
        Set-LabAlertCooldown -Key '10.10.10.30'
        Test-LabAlertCooldown -Key '10.10.10.30' | Should -BeTrue
        Test-LabAlertCooldown -Key '10.10.10.99' | Should -BeFalse
    }
}
