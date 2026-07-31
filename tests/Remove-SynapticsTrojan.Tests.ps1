#Requires -Version 5.1
# Unit tests for the pure (side-effect-free) helpers in Remove-SynapticsTrojan.ps1.
# Dot-sourcing the script loads its functions without performing any cleanup.

BeforeAll {
    . "$PSScriptRoot\..\Remove-SynapticsTrojan.ps1" -DryRun
}

Describe 'Get-ExeFromCommand' {
    It 'extracts a quoted path with spaces' {
        Get-ExeFromCommand '"C:\Program Files\Foo Bar\app.exe" -silent' |
            Should -Be 'C:\Program Files\Foo Bar\app.exe'
    }
    It 'extracts an unquoted absolute path' {
        Get-ExeFromCommand 'C:\ProgramData\Synaptics\Synaptics.exe /run' |
            Should -Be 'C:\ProgramData\Synaptics\Synaptics.exe'
    }
    It 'extracts a bare executable name' {
        Get-ExeFromCommand 'wszui.exe --quiet' | Should -Be 'wszui.exe'
    }
    It 'returns nothing when no executable is referenced' {
        Get-ExeFromCommand 'notepad something.txt' | Should -BeNullOrEmpty
    }
    It 'returns nothing for empty input' {
        Get-ExeFromCommand '' | Should -BeNullOrEmpty
    }
}

Describe 'Test-CommandIsMalicious' {
    It 'flags a command referencing the family name with an unverifiable exe' {
        Test-CommandIsMalicious 'C:\ProgramData\Synaptics\Synaptics.exe' | Should -BeTrue
    }
    It 'flags the wszui helper name' {
        Test-CommandIsMalicious 'C:\Users\victim\wszui.exe -boot' | Should -BeTrue
    }
    It 'ignores unrelated commands' {
        Test-CommandIsMalicious 'C:\Windows\notepad.exe' | Should -BeFalse
    }
    It 'ignores explorer.exe (clean Winlogon Shell value)' {
        Test-CommandIsMalicious 'explorer.exe' | Should -BeFalse
    }
    It 'ignores empty input' {
        Test-CommandIsMalicious '' | Should -BeFalse
    }
}

Describe 'Test-HostsLineIsMalicious' {
    It 'flags a sinkholed antivirus domain' {
        Test-HostsLineIsMalicious '0.0.0.0 www.avast.com' | Should -BeTrue
    }
    It 'flags a loopback-mapped update domain with multiple hosts' {
        Test-HostsLineIsMalicious '127.0.0.1 windowsupdate.com download.windowsupdate.com' | Should -BeTrue
    }
    It 'keeps comment lines' {
        Test-HostsLineIsMalicious '# 0.0.0.0 www.avast.com (disabled)' | Should -BeFalse
    }
    It 'keeps ordinary custom entries' {
        Test-HostsLineIsMalicious '192.168.1.10 mynas' | Should -BeFalse
    }
    It 'keeps the localhost entry' {
        Test-HostsLineIsMalicious '127.0.0.1 localhost' | Should -BeFalse
    }
    It 'keeps blank and malformed lines' {
        Test-HostsLineIsMalicious '' | Should -BeFalse
        Test-HostsLineIsMalicious '0.0.0.0' | Should -BeFalse
    }
    It 'keeps a security domain mapped to a real address' {
        Test-HostsLineIsMalicious '13.107.4.50 windowsupdate.com' | Should -BeFalse
    }
}

Describe 'Get-CacheOriginalName' {
    It 'strips the ._cache_ prefix' {
        Get-CacheOriginalName '._cache_MyGame.exe' | Should -Be 'MyGame.exe'
    }
    It 'returns nothing for names without the prefix' {
        Get-CacheOriginalName 'MyGame.exe' | Should -BeNullOrEmpty
    }
}

Describe 'Test-IsUnderTrustedRoot' {
    It 'is true inside the trusted driver tree' {
        Test-IsUnderTrustedRoot (Join-Path $env:ProgramFiles 'Synaptics\SynTP\SynTPEnh.exe') | Should -BeTrue
    }
    It 'is false for the classic malware drop path' {
        Test-IsUnderTrustedRoot 'C:\ProgramData\Synaptics\Synaptics.exe' | Should -BeFalse
    }
    It 'is false for empty input' {
        Test-IsUnderTrustedRoot '' | Should -BeFalse
    }
}
