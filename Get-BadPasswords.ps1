<#
  .SYNOPSIS
    Compare password hashes of enabled Active Directory users with one or more lists of bad, weak or non-compliant passwords (e.g. hackers first guess during a brute-force attack).
    - Multiple word lists can be used.
    - Can write log and CSV file output.
    - Must be excuted with 'Domain Admin' or 'Domain Controller' permissions (or equivalent).
    
    Requires PS Module "DSInternals" to be present on executing host. Please follow install instructions from there.
    - Found here: https://www.powershellgallery.com/packages/DSInternals/
    - More info:  https://www.dsinternals.com/en/
    Note: this script does not modify or permutate input from word lists, like switching to upper/lower case etc. Each word in word list is taken as-is. Use other tools to generate word lists if needed.
	
  .DESCRIPTION
    Compare password hashes of active Active Directory users with list of bad, weak or non-compliant passwords.
  .PARAMETER arrBadPasswordFiles / Wordlists
    Input paths for word lists with weak passwords. Only "BadPasswords.txt" is used if nothing specified.
  .PARAMETER strDomainController / DC / DomainController
    Input name of the Domain Controller to query, e.g. "DC1".
  .PARAMETER strNamingContext / NC / NamingContext
    Input the AD Naming Context, e.g. "DC=AD,DC=HEIDELBERG,DC=NU".
  .PARAMETER bolWriteToCsvFile / WriteToCsvFile / CSV
    Create dump CSV file of users with weak passwords.
  .PARAMETER bolWriteToLogFile / WriteToLogFile / Log
    Create log file with script execution status.
  .PARAMETER bolWriteVerboseInfoToLogfile / WriteVerboseInfoToLogfile / LogVerbose
    Make the log file verbose - more detailed logging.
  .PARAMETER bolWriteClearTextPasswordsToLogFile / WriteClearTextPasswordsToLogFile / LogPasswords
    Write clear text value of detected weak passwords to log file.
  .EXAMPLE
    PS C:\> Get-bADpasswords -DC 'DC1' -NC 'DC=AD,DC=HEIDELBERG,DC=NU' -Log -LogVerbose -LogPasswords -CSV -Wordlists "BadPasswords.txt","Rockyou.txt" -Verbose
    1. Contact 'DC1' and as for users under Naming Context 'DC=AD,DC=HEIDELBERG,DC=NU'
    2. Write a log file (name is hardcoded in script and gets a timestamp for each execution).
    3. Make log file verbose - more detailed information.
    4. Also log clear text (weak) passwords in the log file.
    5. Dump CSV file of users with weak passwords. Use file for e.g. warning-email or force password change on next logon (other script/system).
    6. Use two word lists, "BadPasswords.txt" and "Rockyou.txt", from current directory.
    7. Verbose logging to console.
  .EXAMPLE
    PS C:\> Get-bADpasswords -DC 'DC1' -NC 'DC=AD,DC=HEIDELBERG,DC=NU' -Wordlists "C:\Wordlists\OtherBadPasswords.txt" -Verbose
    
    1. This will change the word list input to another file in another directory.
    2. Verbose logging to console.
  .EXAMPLE
    PS C:\> Get-bADpasswords -DC 'DC1' -NC 'DC=AD,DC=HEIDELBERG,DC=NU' -CSV
    
    1. This could be for running as a Scheduled Task e.g. on a DC as SYSTEM.
    2. Will just dump CSV file of users with weak passwords. Use file for e.g. warning-email or force password change on next logon (other script/system).
  .LINK
    Get latest version here: https://github.com/ZilentJack/Get-bADpasswords
  .NOTES
    Authored by    : Jakob H. Heidelberg / @JakobHeidelberg
    Date created   : 01/10-2015
    Last modified  : 11/10-2015
    The very cool DSInternals module is authored by Michael Grafnetter - HUGE THANX to Michael for his great work and help! 
    Version history:
    - 1.00: Initial version (02/10-2015)
    - 1.01: Added help information on parameters, renamed booleans (02/10-2015)
    - 1.02: Fixed error on empty lines in input files (word lists)
            Exception calling "ContainsKey" with "1" argument(s): "Key cannot be null. Parameter name: key" [ArgumentNullException]
    - 1.03: Default test for blank passwords, NT hash: 31d6cfe0d16ae931b73c59d7e0c089c0
    - 1.04: Fixed error on null value for user passwords, e.g. PS> New-ADUser NullPwdUser1 -PasswordNotRequired $true -Enabled $true
    - 1.05: Added comments on hashtable $htBadPasswords - case-insensitive on purpose (AAD3B435B51404EEAAD3B435B51404EE == aad3B435b51404eeaad3B435B51404ee)
    
    Tested on:
     - WS 2012 R2 with WMF 5.0 Production Preview (both from member-server and from DC)
    Known Issues & possible solutions:
     KI-0001: - none at this point -
    Change Requests (not prioritized, may or may not be implemented in future version):
     CR-0001: Force end-users with weak passwords to change password on next logon.
     CR-0002: Send e-mail to end-user with weak passwords and/or IT Security Manager.
     CR-0003: Do permutations on input from word lists, like add current year etc. (better tools for this out there).
     CR-0004: Make log & CSV file naming (and timestamp) optional.
    Verbose output:
     Use -Verbose to output script progress/status information to console.
#>

Function Get-bADpasswords
{
  [CmdletBinding()]
  param
  (
    [Parameter(HelpMessage = 'Input paths for word lists with weak passwords. Only "BadPasswords.txt" is used if nothing specified.')]
    [alias("Wordlists")]
    [array]
    $arrBadPasswordFiles = @('BadPasswords.txt'),

    [Parameter(HelpMessage = 'Input name of the Domain Controller to query, e.g. "DC1".', Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [alias("DC","DomainController")]
    [string]
    $strDomainController,

    [Parameter(HelpMessage = 'Input the AD Naming Context, e.g. "DC=AD,DC=HEIDELBERG,DC=NU".', Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [alias("NC","NamingContext")]
    [string]
    $strNamingContext,

    [Parameter(HelpMessage = 'Create dump CSV file of users with weak passwords.')]
    [alias("CSV")]
    [switch]
    $bolWriteToCsvFile,

    [Parameter(HelpMessage = 'Create log file with script execution status.')]
    [alias("Log")]
    [Switch]
    $bolWriteToLogFile,

    [Parameter(HelpMessage = 'Make the log file verbose - more detailed logging.')]
    [alias("LogVerbose")]
    [switch]
    $bolWriteVerboseInfoToLogfile,

    [Parameter(HelpMessage = 'Write clear text value of weak passwords to log file.')]
    [alias("LogPasswords")]
    [switch]
    $bolWriteClearTextPasswordsToLogFile
  )
  
    # ============ #
    # VARIABLES => #
    # ============ #
    $ScriptVersion = "1.05"

    # Set log/CSV file names with date/time
    $LogTimeStamp = Get-Date -Format ddMMyyyy-HHmmss
    $LogFileName  = "Get-bADpasswords_$LogTimeStamp.txt"
    $CsvFileName  = "Get-bADpasswords_$LogTimeStamp.csv"

    # Counters
    $intBadPasswordsFound = 0
    $intBadPasswordsInLists = 0
    $intBadPasswordsInListsDuplicates = 0
    $intUsersAndHashesFromAD = 0
    $intNullPasswordsFound = 0
    $intIdenticalPairsFound = 0

    # Constant
    $strBlankPasswordNThash = '31d6cfe0d16ae931b73c59d7e0c089c0'

    # ============ #
    # FUNCTIONS => #
    # ============ #

    Function LogWrite
    {
        Param
        (
            [string]$Logfile,
            [string]$LogEntryString,
            [ValidateSet("INFO","DATA","FAIL")][string]$LogEntryType,
            [switch]$TimeStamp
        )

        If ($TimeStamp -and $LogEntryType -and $LogEntryString)
        {
            $TimeNow = Get-Date -Format dd.MM.yyyy-HH:mm:ss
            Add-content $Logfile -Value "$TimeNow`t$LogEntryType`t$LogEntryString"
        }
        ElseIf ($TimeStamp -and $LogEntryString)
        {
            $TimeNow = Get-Date -Format dd.MM.yyyy-HH:mm:ss
            Add-content $Logfile -Value "$TimeNow`t$LogEntryString"
        }
        ElseIf ($LogEntryType -and $LogEntryString)
        {
            Add-content $Logfile -Value "$LogEntryType`t$LogEntryString"
        }
        Else
        {
            Add-content $Logfile -Value "$LogEntryString"
        }
    }

    Function Get-NTHashFromClearText
    {
        # Usage: Get-NTHashFromClearText -ClearTextPassword 'Pa$$W0rd' > 36185099f86b48b5af3cc46edd16efca
        Param ([string]$ClearTextPassword)
        Return ConvertTo-NTHash $(ConvertTo-SecureString $ClearTextPassword -AsPlainText -Force)
    }

    Function GetOut
    {
        If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "Ended" -LogEntryType INFO -TimeStamp}
        Write-Verbose "Ended"
        Break
    }


    # ============ #
    # SCRIPT    => #
    # ============ #

    If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "Started" -LogEntryType INFO -TimeStamp}
    If ($bolWriteToLogFile -and $bolWriteVerboseInfoToLogfile) {LogWrite -Logfile $LogFileName -LogEntryString "| Version: $ScriptVersion" -LogEntryType INFO -TimeStamp}
    If ($bolWriteToLogFile -and $bolWriteVerboseInfoToLogfile) {LogWrite -Logfile $LogFileName -LogEntryString "| Logfile: $LogFileName" -LogEntryType INFO -TimeStamp}
    If ($bolWriteToLogFile -and $bolWriteVerboseInfoToLogfile) {LogWrite -Logfile $LogFileName -LogEntryString "| CSVfile: $CsvFileName" -LogEntryType INFO -TimeStamp}

    # Create empty hash table for bad/weak passwords (case-insensitive on purpose)
    $htBadPasswords = @{}

    # Populate array with usernames and NT hash values for enabled users only
    Write-Verbose "Calling Get-ADReplAccount with parameters..."
    If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "Calling Get-ADReplAccount with parameters..." -LogEntryType INFO -TimeStamp}
    If ($bolWriteToLogFile -and $bolWriteVerboseInfoToLogfile) {LogWrite -Logfile $LogFileName -LogEntryString "| DC: $strDomainController" -LogEntryType INFO -TimeStamp}
    If ($bolWriteToLogFile -and $bolWriteVerboseInfoToLogfile) {LogWrite -Logfile $LogFileName -LogEntryString "| NC: $strNamingContext" -LogEntryType INFO -TimeStamp}

    # Set array to NULL for usage in ISE
    $arrUsersAndHashes = $null

    Try
    {
        $arrUsersAndHashes = Get-ADReplAccount -All -Server $strDomainController -NamingContext $strNamingContext | Where {$_.Enabled -eq $true -and $_.SamAccountType -eq 'User'} | Select SamAccountName,@{Name="NTHashHex";Expression={ConvertTo-Hex $_.NTHash}}
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString $ErrorMessage -LogEntryType FAIL -TimeStamp}
        Write-Verbose "FAIL: $ErrorMessage"
    }

    $intUsersAndHashesFromAD = $arrUsersAndHashes.Count

    # We can only continue, if we got users and hashes
    If ($intUsersAndHashesFromAD -lt 1)
    {
        If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "No data from AD - will quit!" -LogEntryType FAIL -TimeStamp}
        Write-Verbose "No data from AD - will quit!"
        GetOut
    }

    # Let's deliver the good news
    If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "AD returned $intUsersAndHashesFromAD usernames and NT hashes!" -LogEntryType DATA -TimeStamp}
    Write-Verbose "AD returned $intUsersAndHashesFromAD usernames and NT hashes!"

    # Add blank password NT hash to hashtable
    If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "Adding blank password NT hash to hashtable..." -LogEntryType INFO -TimeStamp}
    Write-Verbose "Adding blank password NT hash to hashtable..."
    $htBadPasswords.Add($strBlankPasswordNThash,"")

    If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "Loading bad password word lists..." -LogEntryType INFO -TimeStamp}
    Write-Verbose "Loading bad password word lists..."

    # Load each word list
    Foreach ($WordlistPath in $arrBadPasswordFiles)
    {
        If ($bolWriteToLogFile -and $bolWriteVerboseInfoToLogfile) {LogWrite -Logfile $LogFileName -LogEntryString "| Checking word list: $WordlistPath" -LogEntryType INFO -TimeStamp}
        Write-Verbose "| Checking word list: $WordlistPath"

        If (Test-Path $WordlistPath)
        {
            If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "Word list file found: $WordlistPath" -LogEntryType INFO -TimeStamp}
            Write-Verbose "Word list file found: $WordlistPath"
        
            $BadPasswordList = Get-Content -Path $WordlistPath
            $cnt_LineNumber = 1

            Foreach ($BadPassword in $BadPasswordList)
            {
                
                # Detect and ignore emty strings
                If ($BadPassword -eq '')
                {
                    If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "| Empty input line ignored (line#: $cnt_LineNumber)." -LogEntryType INFO -TimeStamp}
                    Write-Verbose "| Empty input line ignored (line#: $cnt_LineNumber)."
                    $cnt_LineNumber++
                    Continue
                }

                $NTHash = $(Get-NTHashFromClearText $BadPassword)

                If ($htBadPasswords.ContainsKey($NTHash)) # NB! Case-insensitive on purpose
                {
                    $intBadPasswordsInListsDuplicates++
                    If ($bolWriteToLogFile -and $bolWriteVerboseInfoToLogfile) {LogWrite -Logfile $LogFileName -LogEntryString "| Duplicate password: '$BadPassword' = $NTHash" -LogEntryType INFO -TimeStamp}
                    Write-Verbose "| Duplicate password: '$BadPassword' = $NTHash (line#: $cnt_LineNumber)"
                }
                Else # New password to put into hash table
                {
                    If ($bolWriteToLogFile -and $bolWriteVerboseInfoToLogfile) {LogWrite -Logfile $LogFileName -LogEntryString "| Adding to hashtable: '$BadPassword' = $NTHash" -LogEntryType INFO -TimeStamp}
                    Write-Verbose "| Adding to hashtable: '$BadPassword' = $NTHash (line#: $cnt_LineNumber)"
                    $htBadPasswords.Add($NTHash,$BadPassword)
                }

                # Counting line numbers
                $cnt_LineNumber++

            } # Foreach BadPassword

        }
        Else # Word list not found
        {
            If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "Word list not found: $WordlistPath" -LogEntryType FAIL -TimeStamp}
            Write-Verbose "Word list not found: $WordlistPath"
        }

    } # Foreach BadPassword file

    $intBadPasswordsInLists = $htBadPasswords.Count - 1 # Count minus 1 because: blank password NT hash added by default, not from lists...

    # We can only continue, if we got weak passwords from word lists
    If ($intBadPasswordsInLists -lt 1)
    {
        If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "No data from word lists - will quit!" -LogEntryType FAIL -TimeStamp}
        Write-Verbose "No data from word lists - will quit!"
        GetOut
    }

    # Let's deliver the good news
    If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "Word lists had a total of $intBadPasswordsInLists unique weak passwords!" -LogEntryType DATA -TimeStamp}
    Write-Verbose "Word lists had a total of $intBadPasswordsInLists unique weak passwords!"

    If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "Word lists had a total of $intBadPasswordsInListsDuplicates duplicate weak passwords!" -LogEntryType DATA -TimeStamp}
    Write-Verbose "Word lists had a total of $intBadPasswordsInListsDuplicates duplicate weak passwords!"

    Foreach ($objUser in $arrUsersAndHashes)
    {
        $strUserSamAccountName = $objUser.SamAccountName
        $strUserNTHashHex = $objUser.NTHashHex

        If ($strUserNTHashHex -eq $null)
        {
            If ($bolWriteToLogFile -and $bolWriteVerboseInfoToLogfile) {LogWrite -Logfile $LogFileName -LogEntryString "Null password found for user: $strUserSamAccountName" -LogEntryType INFO -TimeStamp}
            Write-Verbose "Null password found for user: $strUserSamAccountName"
            $intNullPasswordsFound++
            Continue
        }
        If ($bolWriteToLogFile -and $bolWriteVerboseInfoToLogfile) {LogWrite -Logfile $LogFileName -LogEntryString "| Checking password hash of user: $strUserSamAccountName = $strUserNTHashHex" -LogEntryType INFO -TimeStamp}
        Write-Verbose "Checking password hash of user: $strUserSamAccountName = $strUserNTHashHex"
    
        If ($htBadPasswords.ContainsKey($strUserNTHashHex)) # NB! Case-insensitive on purpose
        {
            $intBadPasswordsFound++
            $strUserBadPasswordClearText = $htBadPasswords.Get_Item($strUserNTHashHex)
            If ($bolWriteToLogFile)
            {
                If ($bolWriteClearTextPasswordsToLogFile){LogWrite -Logfile $LogFileName -LogEntryString "Weak password found for user: $strUserSamAccountName = '$strUserBadPasswordClearText'" -LogEntryType INFO -TimeStamp}
                Else {LogWrite -Logfile $LogFileName -LogEntryString "Weak password found for user: $strUserSamAccountName" -LogEntryType INFO -TimeStamp}
            }
            Write-Verbose "| Weak password found for user: $strUserSamAccountName = '$strUserBadPasswordClearText'"
            If(dsquery user -samid ($strUserSamAccountName+"-a"))
            {
                Write-Verbose "| Linked admin user found. Looking for identical password"
                $linkedAdmin = Get-ADReplAccount -SamAccountName ($strUserSamAccountName+"-a") -Server $strDomainController -Domain exproject | Where {$_.Enabled -eq $true -and $_.SamAccountType -eq 'User'} | Select SamAccountName,@{Name="NTHashHex";Expression={ConvertTo-Hex $_.NTHash}}
                if($linkedAdmin.NTHashHex -eq $strUserNTHashHex)
                {
                    If ($bolWriteToLogFile)
                    {
                        LogWrite -Logfile $LogFileName -LogEntryString "Identical password found for linked admin user: $strUserSamAccountName" -LogEntryType INFO -TimeStamp
                    }
                    Write-Verbose "|| Identical password for $strUserSamAccountName and linked admin user."
                    $intIdenticalPairsFound++
                }
            } 

            # Handle CSV fil output
            If ($bolWriteToCsvFile)
            {
                LogWrite -Logfile $CsvFileName -LogEntryString "$strUserSamAccountName;$strUserNTHashHex"
            }
        }
        Else
        {
            If ($bolWriteToLogFile -and $bolWriteVerboseInfoToLogfile) {LogWrite -Logfile $LogFileName -LogEntryString "| Compliant password for user: $strUserSamAccountName" -LogEntryType INFO -TimeStamp}
            Write-Verbose "| Compliant password for user: $strUserSamAccountName"
        }
    }

    # Give status on found weak passwords
    If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "Found $intBadPasswordsFound user(s) with weak password!" -LogEntryType DATA -TimeStamp}
    Write-Verbose "Found $intBadPasswordsFound user(s) with weak password!"

    # Give status on found $null passwords
    If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "Found $intNullPasswordsFound user(s) with null password!" -LogEntryType DATA -TimeStamp}
    Write-Verbose "Found $intNullPasswordsFound user(s) with null password!"

    # Give status on found identical password pairs
    If ($bolWriteToLogFile) {LogWrite -Logfile $LogFileName -LogEntryString "Found $intIdenticalPairsFound identical user / admin pairs" -LogEntryType DATA -TimeStamp}
    Write-Verbose "Found $intIdenticalPairsFound identical user / admin pairs!"

    # Let's exit gracefully
    GetOut

} # Get-bADpasswords function end