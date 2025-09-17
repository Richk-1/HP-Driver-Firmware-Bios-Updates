<#

.SYNOPSIS
PSAppDeployToolkit - This script performs the installation or uninstallation of an application(s).

.DESCRIPTION
- The script is provided as a template to perform an install, uninstall, or repair of an application(s).
- The script either performs an "Install", "Uninstall", or "Repair" deployment type.
- The install deployment type is broken down into 3 main sections/phases: Pre-Install, Install, and Post-Install.

The script imports the PSAppDeployToolkit module which contains the logic and functions required to install or uninstall an application.

.PARAMETER DeploymentType
The type of deployment to perform.

.PARAMETER DeployMode
Specifies whether the installation should be run in Interactive (shows dialogs), Silent (no dialogs), NonInteractive (dialogs without prompts) mode, or Auto (shows dialogs if a user is logged on, device is not in the OOBE, and there's no running apps to close).

Silent mode is automatically set if it is detected that the process is not user interactive, no users are logged on, the device is in Autopilot mode, or there's specified processes to close that are currently running.

.PARAMETER SuppressRebootPassThru
Suppresses the 3010 return code (requires restart) from being passed back to the parent process (e.g. SCCM) if detected from an installation. If 3010 is passed back to SCCM, a reboot prompt will be triggered.

.PARAMETER TerminalServerMode
Changes to "user install mode" and back to "user execute mode" for installing/uninstalling applications for Remote Desktop Session Hosts/Citrix servers.

.PARAMETER DisableLogging
Disables logging to file for the script.

.EXAMPLE
powershell.exe -File Invoke-AppDeployToolkit.ps1

.EXAMPLE
powershell.exe -File Invoke-AppDeployToolkit.ps1 -DeployMode Silent

.EXAMPLE
powershell.exe -File Invoke-AppDeployToolkit.ps1 -DeploymentType Uninstall

.EXAMPLE
Invoke-AppDeployToolkit.exe -DeploymentType Install -DeployMode Silent

.INPUTS
None. You cannot pipe objects to this script.

.OUTPUTS
None. This script does not generate any output.

.NOTES
Toolkit Exit Code Ranges:
- 60000 - 68999: Reserved for built-in exit codes in Invoke-AppDeployToolkit.ps1, and Invoke-AppDeployToolkit.exe
- 69000 - 69999: Recommended for user customized exit codes in Invoke-AppDeployToolkit.ps1
- 70000 - 79999: Recommended for user customized exit codes in PSAppDeployToolkit.Extensions module.

.LINK
https://psappdeploytoolkit.com

#>

[CmdletBinding()]
param
(
    # Default is 'Install'.
    [Parameter(Mandatory = $false)]
    [ValidateSet('Install', 'Uninstall', 'Repair')]
    [System.String]$DeploymentType,

    # Default is 'Auto'. Don't hard-code this unless required.
    [Parameter(Mandatory = $false)]
    [ValidateSet('Auto', 'Interactive', 'NonInteractive', 'Silent')]
    [System.String]$DeployMode,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$SuppressRebootPassThru,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$TerminalServerMode,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$DisableLogging
)


##================================================
## MARK: Variables
##================================================

# Zero-Config MSI support is provided when "AppName" is null or empty.
# By setting the "AppName" property, Zero-Config MSI will be disabled.
$adtSession = @{
    # App variables.
    AppVendor = 'HP'
    AppName = 'Driver Firmware BIOS Updates'
    AppVersion = '1.0'
    AppArch = 'x64'
    AppLang = 'EN'
    AppRevision = '01'
    AppSuccessExitCodes = @(0)
    AppRebootExitCodes = @(1641, 3010)
    AppProcessesToClose = @()  # Example: @('excel', @{ Name = 'winword'; Description = 'Microsoft Word' })
    AppScriptVersion = '1.0.0'
    AppScriptDate = '09/17/2025'
    AppScriptAuthor = ''
    RequireAdmin = $true

    # Install Titles (Only set here to override defaults set by the toolkit).
    InstallName = ''
    InstallTitle = ''

    # Script variables.
    DeployAppScriptFriendlyName = $MyInvocation.MyCommand.Name
    DeployAppScriptParameters = $PSBoundParameters
    DeployAppScriptVersion = '4.1.5'
}

function Install-ADTDeployment
{
        ##*===============================================
        ##* PRE-INSTALLATION
        ##*===============================================
        $adtSession.InstallPhase = "Pre-$($adtSession.DeploymentType)"

        Show-ADTInstallationWelcome -AllowDefer -ForceCountdown '3600' -DeferTimes 3
        Show-ADTInstallationProgress -StatusMessage 'Updating device drivers and bios, please ignore any restart prompts and wait for this window to update'

        ##*======== =======================================
        ##* INSTALLATION
        ##*===============================================
        $adtSession.InstallPhase = $adtSession.DeploymentType

    $StartTime = Get-Date
        		Set-ADTRegistryKey -Key 'HKLM:\SOFTWARE\HP\ImageAssistant' -Name 'StartTime' -Value $StartTime -Type String

        		$Date = (Get-Date -Format "MM-dd-yyyy HH:mm")
        		$HPBiosPwdCache = Join-Path -Path $env:SystemRoot -ChildPath "Temp\HPCache"
        		$HPBiosPwdFile = "$HPBiosPwdCache\PASS.bin"
        		$HPImageAssistantExtractPath = Join-Path -Path $env:SystemRoot -ChildPath "Temp\HPIA"
        		$HPImageAssistantReportPath = Join-Path -Path $env:SystemRoot -ChildPath "Temp\HPIALogs"
        		$SoftpaqDownloadPath = Join-Path -Path $env:SystemRoot -ChildPath "Temp\HPDrivers"
        		$HPImageAssistantExecutablePath = Join-Path -Path $env:SystemRoot -ChildPath "Temp\HPIA\HPImageAssistant.exe"
        		$HPReportFinal = Join-Path $env:SystemRoot -ChildPath "Logs\Software\HP"
        		$HPImageAssistantArguments = "/Operation:Analyze /Action:Install /Selection:All /Silent /Category:All /ReportFolder:$($HPImageAssistantReportPath) /SoftpaqDownloadFolder:$($SoftpaqDownloadPath) /BIOSPwdFile:$($HPBiosPwdFile)"

        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'StartTime'
        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'OperationalMode'
        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'OverallHealth'
        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'OverallSeurity'
        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'Drivers Summary Recommended'
        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'Drivers Summary OutOfDate'
        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'Firmware Summary OutOfDate'
        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'Software Summary Recommended'
        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'Software Summary OutOfDate'
        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'Software Summary Recommended Ids'
        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'EndTime'
        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'Exit Code'
        		Remove-ADTRegistryKey -Key HKLM:\SOFTWARE\hp\ImageAssistant -Name 'ExecutionResult'

        		Remove-ADTFolder -Path $HPBiosPwdCache
        		Remove-ADTFolder -Path $HPImageAssistantExtractPath
        		Remove-ADTFolder -Path $HPImageAssistantReportPath
        		Remove-ADTFolder -Path $HPReportFinal

        		New-ADTFolder -Path $HPBiosPwdCache
        		New-ADTFolder -Path $HPImageAssistantExtractPath
        		New-ADTFolder -Path $HPImageAssistantReportPath
        		New-ADTFolder -Path $SoftpaqDownloadPath
        		New-ADTFolder -Path $HPReportFinal

        		Copy-ADTFile -Destination $HPBiosPwdCache -Path "$($adtSession.DirFiles)\PASS.bin"
        		Start-Sleep -Seconds 1
        		if (!(Test-Path -Path "$HPBiosPwdCache\PASS.bin")) {
        			Write-ADTLogEntry -Message 'Pass bin file not found, exiting script' -Severity 2
        			Exit-ADTScript -ExitCode '255'
        		} else {
        			Write-ADTLogEntry -Message 'Pass bin file found' -Severity 1
        		}

        		try {
        			Set-Location -Path (Join-Path -Path $env:SystemRoot -ChildPath "Temp")
        			Install-HPImageAssistant -Extract -DestinationPath $HPImageAssistantExtractPath
        			Pop-Location
        			Write-ADTLogEntry -Message 'Installed HP Image Assistant'
        		}
        		catch {
        			Write-ADTLogEntry -Message 'Failed to install HP Image Assistant' -Severity 2
        		}


        		Write-ADTLogEntry -Message 'Attempting to execute HP Image Assistant to download and install drivers including driver software, this might take some time' -Severity 1
        		Set-ADTRegistryKey -Key 'HKLM:\SOFTWARE\HP\ImageAssistant' -Name 'OperationalMode' -Value 'Install' -Type String
        		Set-ADTRegistryKey -Key 'HKLM:\SOFTWARE\HP\ImageAssistant' -Name 'InstallModeRanLast' -Value "$Date" -Type String

        		$results = Start-ADTProcess -FilePath $HPImageAssistantExecutablePath -ArgumentList $HPImageAssistantArguments -PassThru  -IgnoreExitCodes 0,256,257,3010,3020,8199
        		$HPIAExitCode = $results.ExitCode

        		switch ($HPIAExitCode) {
            0 {
                Write-ADTLogEntry -Message "HP Image Assistant returned successful exit code: $($HPIAExitCode)" -Severity 1
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "ExecutionResult" -Value "Success" -Type String
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Exit Code" -Value "$HPIAExitCode" -Type String
            }
            256 {
                # The analysis returned no recommendations
                Write-ADTLogEntry -Message "HP Image Assistant returned successful exit code: $($HPIAExitCode)" -Severity 1
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "ExecutionResult" -Value "Success" -Type String
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Exit Code" -Value "$HPIAExitCode" -Type String
            }
        	257 {
                # The analysis returned no recommendations
                Write-ADTLogEntry -Message "HP Image Assistant returned successful exit code: $($HPIAExitCode)" -Severity 1
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "ExecutionResult" -Value "Success" -Type String
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Exit Code" -Value "$HPIAExitCode" -Type String
            }
            3010 {
                # Softpaqs installations are successful, but at least one requires a restart
                Write-ADTLogEntry -Message "HP Image Assistant returned successful exit code: $($HPIAExitCode)" -Severity 1
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "ExecutionResult" -Value "Success" -Type String
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Exit Code" -Value "$HPIAExitCode" -Type String
            }
            3020 {
                # One or more Softpaq's failed to install
                Write-ADTLogEntry -Message "HP Image Assistant did not install one or more softpaqs successfully, examine the Readme*.html file in: $($HPImageAssistantReportPath)" -Severity 2
                Write-ADTLogEntry -Message "HP Image Assistant returned successful exit code: $($HPIAExitCode)" -Severity 1
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "ExecutionResult" -Value "Success" -Type String
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Exit Code" -Value "$HPIAExitCode" -Type String
            }
        	8199 {
                # One or more Softpaq's failed to download
                Write-ADTLogEntry -Message "HP Image Assistant did not install one or more softpaqs successfully, examine the Readme*.html file in: $($HPImageAssistantReportPath)" -Severity 2
                Write-ADTLogEntry -Message "HP Image Assistant returned successful exit code: $($HPIAExitCode)" -Severity 1
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "ExecutionResult" -Value "Success" -Type String
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Exit Code" -Value "$HPIAExitCode" -Type String
            }
            default {
                Write-ADTLogEntry -Message "HP Image Assistant returned unhandled exit code: $($Invocation)" -Severity 3
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "ExecutionResult" -Value "Failed" -Type String
                Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Exit Code" -Value "Failed" -Type string
            }
        }

        		$HPModel = Get-HPDeviceModel
            	$HPxml = "C:\windows\temp\HPIALogs\$HPModel.xml"
            	if (Test-Path -Path "$HPxml") {
        [xml]$XmlDocument = Get-Content -Path "$HPxml"

        if ($XmlDocument.HPIA.OverallHealth) {
        			Set-ADTRegistryKey -Key 'HKLM:\SOFTWARE\HP\ImageAssistant' -Name 'OverallHealth' -Value $XmlDocument.HPIA.OverallHealth -Type String
        }

        if ($XmlDocument.HPIA.OverallSeurity) {
            Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "OverallSeurity" -Value $XmlDocument.HPIA.OverallSeurity -Type String
        }

        if ($XmlDocument.HPIA.Summary.Drivers.Recommended) {
            Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Drivers Summary Recommended" -Value $XmlDocument.HPIA.Summary.Drivers.Recommended -Type String
        }

        if ($XmlDocument.HPIA.Summary.Drivers.OutOfDate) {
            Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Drivers Summary OutOfDate" -Value $XmlDocument.HPIA.Summary.Drivers.OutOfDate -Type String
        }

        if ($XmlDocument.HPIA.Summary.Firmware.OutOfDate) {
            Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Firmware Summary OutOfDate" -Value $XmlDocument.HPIA.Summary.Firmware.OutOfDate -Type String
        }

        if ($XmlDocument.HPIA.Summary.Software.Recommended) {
            Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Software Summary Recommended" -Value $XmlDocument.HPIA.Summary.Software.Recommended -Type String
        }

        if ($XmlDocument.HPIA.Summary.Software.OutOfDate) {
            Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Software Summary OutOfDate" -Value $XmlDocument.HPIA.Summary.Software.OutOfDate -Type String
        }

        if ($XmlDocument.HPIA.Recommendations.Software.Recommendation.solution.softpaq.Id) {
            Set-ADTRegistryKey -Key "HKLM:\SOFTWARE\HP\ImageAssistant" -Name "Software Summary Recommended Ids" -Value ($XmlDocument.HPIA.Recommendations.Software.Recommendation.solution.softpaq.Id | Out-String) -Type String
        }
            }

        		if (Test-Path -Path 'C:\Windows\Temp\HPDriverUpdate.log') {
        			try {
        				Copy-ADTFile -Path 'C:\Windows\Temp\HPDriverUpdate.log' -Destination "$HPReportFinal"
        				Write-ADTLogEntry -Message "Copied HPDriverUpdate.log to: $($HPReportFinal)" -Severity 1
        			}
        			catch {
        				Write-ADTLogEntry -Message "Failed to copy HPDriverUpdate.log to: $($HPReportFinal)" -Severity 3
        			}
        		}

        		if (Test-Path -Path 'C:\WINDOWS\Temp\HPIALogs') {
        			try {
        				Copy-ADTFile -Path 'C:\WINDOWS\Temp\HPIALogs' -Destination "$HPReportFinal" -Recurse
        				Write-ADTLogEntry -Message "Copied C:\WINDOWS\Temp\HPIALogs to: $($HPReportFinal)" -Severity 1
        			}
        			catch {
        				Write-ADTLogEntry -Message "Failed to copy C:\WINDOWS\Temp\HPIALogs to: $($HPReportFinal)" -Severity 3
        			}
        		}

        		Remove-ADTFolder -Path $SoftpaqDownloadPath
        		Remove-ADTFolder -Path $HPImageAssistantExtractPath
                Remove-ADTFolder -Path $HPBiosPwdCache

        		$EndTime = Get-Date
        		Set-ADTRegistryKey -Key 'HKLM:\SOFTWARE\HP\ImageAssistant' -Name 'EndTime' -Value "$EndTime" -Type String

        		Show-ADTInstallationRestartPrompt -NoCountdown

        ##*===============================================
        ##* POST-INSTALLATION
        ##*===============================================
        $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

        Show-ADTInstallationPrompt -Message "The software was successfully installed." -ButtonRightText 'OK' -Icon Information -NoWait

        ## Master Wrapper detection
    Set-ADTRegistryKey -Key "HKLM\SOFTWARE\InstalledApps\HP_Driver Firmware BIOS Updates_1.0"

        Function Set-RegistryCleanupTask {
            $TaskName = 'HP Driver Firmware Bios Updates'
            # Trigger to run the task once, 5 minutes after being created
            $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(60)
            # Define the action to delete the registry key and unregister the task afterward
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command `"Remove-Item -Path 'HKLM:\SOFTWARE\InstalledApps\HP_Driver Firmware BIOS Updates_1.0' -Recurse -Force; Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false`""
            # Create settings for the task
            $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            # Create the task object and set it to run in the SYSTEM context
            $Newtask = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $settings
            # Set the task to run with the SYSTEM account and with the highest privileges
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
            $Newtask.Principal = $principal
            # Register the scheduled task
            $Newtask | Register-ScheduledTask -TaskName $TaskName
        }

        Set-RegistryCleanupTask

    }

function Uninstall-ADTDeployment
{
        ##*===============================================
        ##* PRE-UNINSTALLATION
        ##*===============================================
        $adtSession.InstallPhase = "Pre-$($adtSession.DeploymentType)"

        ##*===============================================
        ##* UNINSTALLATION
        ##*===============================================
        $adtSession.InstallPhase = $adtSession.DeploymentType

        ##*===============================================
        ##* POST-UNINSTALLATION
        ##*===============================================
        $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

        ## Master Wrapper detection
    Remove-ADTRegistryKey -Key "HKLM\SOFTWARE\InstalledApps\HP_Driver Firmware BIOS Updates_1.0"
    }

function Repair-ADTDeployment
{
        ##*===============================================
        ##* PRE-REPAIR
        ##*===============================================
        $adtSession.InstallPhase = "Pre-$($adtSession.DeploymentType)"

        ##*===============================================
        ##* REPAIR
        ##*===============================================
        $adtSession.InstallPhase = $adtSession.DeploymentType

        ##*===============================================
        ##* POST-REPAIR
        ##*===============================================
        $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

        ## Master Wrapper detection
    Set-ADTRegistryKey -Key "HKLM\SOFTWARE\InstalledApps\HP_Driver Firmware BIOS Updates_1.0"
    }


##================================================
## MARK: Initialization
##================================================

# Set strict error handling across entire operation.
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
$ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
Set-StrictMode -Version 1

# Import the module and instantiate a new session.
try
{
    # Import the module locally if available, otherwise try to find it from PSModulePath.
    if (Test-Path -LiteralPath "$PSScriptRoot\PSAppDeployToolkit\PSAppDeployToolkit.psd1" -PathType Leaf)
    {
        Get-ChildItem -LiteralPath "$PSScriptRoot\PSAppDeployToolkit" -Recurse -File | Unblock-File -ErrorAction Ignore
        Import-Module -FullyQualifiedName @{ ModuleName = "$PSScriptRoot\PSAppDeployToolkit\PSAppDeployToolkit.psd1"; Guid = '8c3c366b-8606-4576-9f2d-4051144f7ca2'; ModuleVersion = '4.1.5' } -Force
    }
    else
    {
        Import-Module -FullyQualifiedName @{ ModuleName = 'PSAppDeployToolkit'; Guid = '8c3c366b-8606-4576-9f2d-4051144f7ca2'; ModuleVersion = '4.1.5' } -Force
    }

    # Open a new deployment session, replacing $adtSession with a DeploymentSession.
    $iadtParams = Get-ADTBoundParametersAndDefaultValues -Invocation $MyInvocation
    $adtSession = Remove-ADTHashtableNullOrEmptyValues -Hashtable $adtSession
    $adtSession = Open-ADTSession @adtSession @iadtParams -PassThru
}
catch
{
    $Host.UI.WriteErrorLine((Out-String -InputObject $_ -Width ([System.Int32]::MaxValue)))
    exit 60008
}


##================================================
## MARK: Invocation
##================================================

# Commence the actual deployment operation.
try
{
    # Import any found extensions before proceeding with the deployment.
    Get-ChildItem -LiteralPath $PSScriptRoot -Directory | & {
        process
        {
            if ($_.Name -match 'PSAppDeployToolkit\..+$')
            {
                Get-ChildItem -LiteralPath $_.FullName -Recurse -File | Unblock-File -ErrorAction Ignore
                Import-Module -Name $_.FullName -Force
            }
        }
    }

    # Invoke the deployment and close out the session.
    & "$($adtSession.DeploymentType)-ADTDeployment"
    Close-ADTSession
}
catch
{
    # An unhandled error has been caught.
    $mainErrorMessage = "An unhandled error within [$($MyInvocation.MyCommand.Name)] has occurred.`n$(Resolve-ADTErrorRecord -ErrorRecord $_)"
    Write-ADTLogEntry -Message $mainErrorMessage -Severity 3

    ## Error details hidden from the user by default. Show a simple dialog with full stack trace:
    # Show-ADTDialogBox -Text $mainErrorMessage -Icon Stop -NoWait

    ## Or, a themed dialog with basic error message:
    # Show-ADTInstallationPrompt -Message "$($adtSession.DeploymentType) failed at line $($_.InvocationInfo.ScriptLineNumber), char $($_.InvocationInfo.OffsetInLine):`n$($_.InvocationInfo.Line.Trim())`n`nMessage:`n$($_.Exception.Message)" -MessageAlignment Left -ButtonRightText OK -Icon Error -NoWait

    Close-ADTSession -ExitCode 60001
}
