# When an azure domain joined system cannot access on premise hosts via e.G. snaffler this script can be used as workaround to directly query shares for secrets
function Invoke-Snaffle {
<#
.SYNOPSIS
    Threaded network share crawler with rules ported 1:1 from Snaffler source (SnaffCon/Snaffler).
    Works without AD â€” takes a host list directly.
.PARAMETER hostlist
    Path to a text file with one IP/hostname per line.
.PARAMETER outfile
    Output CSV path (default: snaffler_results.csv in current directory).
.PARAMETER threads
    Number of concurrent host scans (default: 10). Each job inherits your SMB/Kerberos auth.
.PARAMETER maxsizetogrep
    Max file size in bytes to inspect content (default: 1000000 = ~1MB, same as Snaffler).
.PARAMETER depth
    Max directory recursion depth (default: 10).
.PARAMETER german
    Enable German-language filename rules (KennwÃ¶rter, Passwort, ZugÃ¤nge, etc.)
.EXAMPLE
    Invoke-Snaffle -hostlist .\hosts.txt -outfile C:\temp\snaff.csv
    Invoke-Snaffle -hostlist .\hosts.txt -outfile C:\temp\snaff.csv -german
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$hostlist,
    [string]$outfile = "snaffler_results.csv",
    [int]$threads = 10,
    [int]$maxsizetogrep = 1000000,
    [int]$depth = 10,
    [switch]$german
)

if (-not (Test-Path $hostlist)) {
    Write-Host "[-] Host list not found: $hostlist" -ForegroundColor Red
    return
}

$hosts = Get-Content $hostlist | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
Write-Host "[*] Loaded $($hosts.Count) hosts from $hostlist"
Write-Host "[*] Threads: $threads | Max content scan: $maxsizetogrep bytes | Depth: $depth"
Write-Host "[*] Output: $outfile"
if ($german) { Write-Host "[*] German filename rules enabled" -ForegroundColor Cyan }
Write-Host ""

# ============================================================
# Rules ported from Snaffler DefaultRules TOML files
# ============================================================
$rules = @{
    # --------------------------------------------------------
    # DISCARD â€” skip these extensions entirely (no further processing)
    # Source: FileRules/Discard/DiscardByFileExtension.toml
    # --------------------------------------------------------
    DiscardExtension = @(
        '.bmp','.eps','.gif','.ico','.jfi','.jfif','.jif','.jpe','.jpeg','.jpg',
        '.png','.psd','.svg','.tif','.tiff','.webp','.xcf',
        '.ttf','.otf','.lock','.css','.less','.admx','.adml','.xsd','.nse','.xsl'
    )
    # Source: FileRules/Discard/DiscardByFileName.toml
    DiscardFileName = @('jmxremote.password.template','sceregvl.inf')

    # Source: PostMatchRules/DiscardPostMatchByName.toml
    DiscardPostMatchName = @('credentialprovider.idl','pspasswd64.exe','pspasswd.exe','psexec.exe','psexec64.exe')

    # Source: PostMatchRules/DiscardPostMatchByPath.toml
    DiscardPostMatchPath = @('Windows Kits\\10','Git\\mingw64','Git\\usr\\lib',
        'ProgramData\\Microsoft\\NetFramework\\BreadcrumbStore',
        '.MSSQLSERVER\\MSSQL\\Binn\\Templates')

    # --------------------------------------------------------
    # DISCARD â€” skip these directory paths
    # Source: PathRules/Discard/DiscardWinSystemDirs.toml + DiscardLargeFalsePosDirs.toml
    # --------------------------------------------------------
    DiscardPath = @(
        '\\winsxs','\\syswow64','\\system32','\\systemapps',
        '\\windows\\servicing','\\servicing','\\Microsoft.NET\\Framework',
        '\\windows\\immersivecontrolpanel','\\windows\\diagnostics',
        '\\windows\\debug','\\locale','\\chocolatey\\helpers',
        '\\sources\\sxs','\\localization',
        '\\AppData\\Local\\Microsoft','\\AppData\\Roaming\\Microsoft\\Windows',
        '\\AppData\\Roaming\\Microsoft\\Teams','\\wsuscontent',
        '\\Application Data\\Microsoft\\CLR Security Config','\\servicing\\LCU',
        '\\puppet\\share\\doc','\\lib\\ruby','\\lib\\site-packages',
        '\\usr\\share\\doc','node_modules','vendor\\bundle','vendor\\cache',
        '\\doc\\openssl','WindowsPowerShell\\Modules',
        'Reference Assemblies\\Microsoft\\Framework\\.NETFramework',
        'dotnet\\sdk','dotnet\\shared','Windows\\assembly'
    )
    DiscardPathRegex = @('Anaconda3\\\\Lib\\\\test','Python\\d*\\\\Lib',
        'Modules\\\\Microsoft\\.PowerShell\\.Security')

    # ========================================================
    # EXACT FILENAME MATCHES
    # ========================================================

    # --- BLACK ---
    # Source: KeepSSHFilesByFileName.toml
    ExactName_Black_SSH = @('id_rsa','id_dsa','id_ecdsa','id_ed25519')
    # Source: KeepWinHashesByName.toml
    ExactName_Black_WinHash = @('NTDS.DIT','SYSTEM','SAM','SECURITY')
    # Source: KeepNixLocalHashesByName.toml
    ExactName_Black_NixHash = @('shadow','pwd.db','passwd')
    # Source: KeepNetConfigFileByName.toml
    ExactName_Black_NetConfig = @('running-config.cfg','startup-config.cfg','running-config','startup-config')
    # Source: KeepMemDumpByName.toml
    ExactName_Black_MemDump = @('MEMORY.DMP','hiberfil.sys','lsass.dmp','lsass.exe.dmp')
    # Source: KeepCyberArkConfigsByName.toml
    ExactName_Black_CyberArk = @('Psmapp.cred','psmgw.cred','backup.key',
        'MasterReplicationUser.pass','RecPrv.key','ReplicationUser.pass','Server.key',
        'VaultEmergency.pass','VaultUser.pass','Vault.ini','PADR.ini','PARAgent.ini',
        'CACPMScanner.exe.config','PVConfiguration.xml')
    # Source: KeepRemoteAccessConfByName.toml
    ExactName_Black_RemoteAccess = @('mobaxterm.ini','mobaxterm backup.zip','confCons.xml')
    # Source: KeepCloudApiKeysByName.toml
    ExactName_Black_CloudApi = @('.tugboat')

    # --- unsorted.txt additions ---
    # Source: unsorted.txt KeepFilenameExactRed (labeled Green in file but these are cred-adjacent)
    ExactName_Green_Unsorted = @('otr.private_key','Favorites.plist','proxy.config',
        'keystore','keyring','.gitconfig','.dockercfg','key3.db','key4.db','Login Data')

    # --- RED ---
    # Source: KeepConfigByName.toml
    ExactName_Red_Config = @('.htpasswd','accounts.v4')
    # Source: KeepPhpByName.toml
    ExactName_Red_PHP = @('LocalSettings.php')
    # Source: KeepRubyByName.toml
    ExactName_Red_Ruby = @('database.yml','.secret_token.rb','knife.rb','carrierwave.rb','omniauth.rb')
    # Source: KeepPasswordFilesByName.toml
    ExactName_Red_PassFiles = @(
        'passwords.txt','pass.txt','accounts.txt',
        'passwords.doc','pass.doc','accounts.doc',
        'passwords.xls','pass.xls','accounts.xls',
        'passwords.docx','pass.docx','accounts.docx',
        'passwords.xlsx','pass.xlsx','accounts.xlsx',
        'secrets.txt','secrets.doc','secrets.xls','secrets.docx',
        'BitlockerLAPSPasswords.csv','secrets.xlsx')
    # Source: KeepFtpServerConfigByName.toml
    ExactName_Red_FTP = @('proftpdpasswd','filezilla.xml')
    # Source: KeepFtpClientByName.toml
    ExactName_Red_FTPClient = @('recentservers.xml','sftp-config.json')
    # Source: KeepJenkinsByName.toml
    ExactName_Red_Jenkins = @('jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml','credentials.xml')
    # Source: KeepDbMgtConfigByName.toml
    ExactName_Red_DBMgt = @('SqlStudio.bin','.mysql_history','.psql_history','.pgpass',
        '.dbeaver-data-sources.xml','credentials-config.json','dbvis.xml','robomongo.json')
    # Source: KeepGitCredsByName.toml
    ExactName_Red_Git = @('.git-credentials')

    # --- YELLOW ---
    # Source: KeepDomainJoinCredsByName.toml
    ExactName_Yellow_MDT = @('customsettings.ini')
    # Source: KeepDefenderConfigByName.toml
    ExactName_Yellow_Defender = @('SensorConfiguration.json','mdatp_managed.json')

    # --- YELLOW extensions from unsorted.txt ---
    # Source: unsorted.txt KeepExtExactYellow
    Ext_Yellow_Keys = @('.key','.keypair','.jks')

    # --- GREEN ---
    # Source: KeepShellHistoryByName.toml
    ExactName_Green_History = @('.bash_history','.zsh_history','.sh_history','zhistory',
        '.irb_history','ConsoleHost_History.txt')
    # Source: KeepShellRcFilesByName.toml
    ExactName_Green_RC = @('.netrc','_netrc','.exports','.functions','.extra',
        '.npmrc','.env','.bashrc','.profile','.zshrc')

    # ========================================================
    # FILENAME CONTAINS (partial match)
    # ========================================================
    # Source: KeepFilenameContainsPamOrPwdVault.toml â€” Triage=Green
    NameContains_Green = @('passw','secret','credential','thycotic','cyberark')
    # Source: RelayNetConfigByName.toml â€” relay target, used as Green indicator
    NameContains_NetConfig = @('cisco','router','firewall','switch')

    # ========================================================
    # FILENAME ENDSWITH
    # ========================================================
    # Source: RelayPrivKeyByEnding.toml
    NameEndsWith_PrivKey = @('_rsa','_dsa','_ed25519','_ecdsa')

    # ========================================================
    # FILENAME REGEX
    # ========================================================
    # Source: KeepKerberosCredentialsByName.toml â€” Triage=Yellow
    NameRegex_Yellow_Kerberos = @('krb5cc_.*')

    # ========================================================
    # EXTENSION MATCHES
    # ========================================================

    # --- BLACK ---
    # Source: KeepPassMgrsByExtension.toml
    Ext_Black_PassMgr = @('.kdbx','.kdb','.psafe3','.kwallet','.keychain','.agilekeychain','.cred')
    # Source: KeepSSHKeysByFileExtension.toml
    Ext_Black_SSH = @('.ppk')

    # --- RED ---
    # Source: RelayCertByExtension.toml (CheckForKeys)
    Ext_Red_Cert = @('.pem','.der','.pfx','.pk12','.p12','.pkcs12')
    # Source: KeepInfraAsCodeByExtension.toml
    Ext_Red_IAC = @('.cscfg','.ucs','.tfvars')
    # Source: KeepVMDisksByExtension.toml
    Ext_Red_VMDisk = @('.vmdk','.vdi','.vhd','.vhdx')
    # Source: KeepMemDumpByExtension.toml
    Ext_Red_MemDump = @('.dmp')
    # Source: RelayCyberArkByExtension.toml
    Ext_Red_CyberArk = @('.cred','.pass')

    # --- YELLOW ---
    # Source: KeepDatabaseByExtension.toml
    Ext_Yellow_DB = @('.mdf','.sdf','.sqldump','.bak')
    # Source: KeepKerberosCredentialsByExtension.toml
    Ext_Yellow_Kerberos = @('.keytab','.CCACHE')
    # Source: KeepPcapByExtension.toml
    Ext_Yellow_Pcap = @('.pcap','.cap','.pcapng')
    # Source: KeepRemoteAccessConfByExtension.toml
    Ext_Yellow_RemoteAccess = @('.rdg','.rtsz','.rtsx','.ovpn','.tvopt','.sdtid')
    # Source: KeepDeployImageByExtension.toml
    Ext_Yellow_Deploy = @('.wim','.ova','.ovf')

    # ========================================================
    # RELAY EXTENSIONS â€” these get content-scanned with their language-specific + generic rules
    # ========================================================

    # Source: RelayConfigByExtension.toml â€” generic configs scanned for creds
    RelayExt_Config = @('.yaml','.yml','.toml','.xml','.json','.config','.ini','.inf',
        '.cnf','.conf','.properties','.env','.dist','.txt','.sql','.log',
        '.sqlite','.sqlite3','.fdb','.tfvars')
    # Source: RelayPsByExtension.toml
    RelayExt_PS = @('.psd1','.psm1','.ps1')
    # Source: RelayCmdByExtension.toml
    RelayExt_Cmd = @('.bat','.cmd')
    # Source: RelayCSharpByExtension.toml
    RelayExt_CSharp = @('.aspx','.ashx','.asmx','.asp','.cshtml','.cs','.ascx','.config')
    # Source: RelayJavaByExtension.toml
    RelayExt_Java = @('.jsp','.do','.java','.cfm')
    # Source: RelayJsByExtension.toml
    RelayExt_JS = @('.js','.cjs','.mjs','.ts','.tsx','.ls','.es6','.es')
    # Source: RelayPythonByExtension.toml
    RelayExt_Python = @('.py')
    # Source: RelayPhpByExtension.toml
    RelayExt_PHP = @('.php','.phtml','.inc','.php3','.php5','.php7')
    # Source: RelayPerlByExtension.toml
    RelayExt_Perl = @('.pl')
    # Source: RelayRubyByExtension.toml
    RelayExt_Ruby = @('.rb')
    # Source: RelayVBScriptByExtension.toml
    RelayExt_VBS = @('.vbs','.vbe','.wsf','.wsc','.asp','.hta')
    # Source: RelayShellScriptByExtension.toml
    RelayExt_Shell = @('.netrc','.exports','.functions','.extra','.npmrc','.env',
        '.bashrc','.profile','.zshrc','.bash_history','.zsh_history','.sh_history',
        'zhistory','.irb_history')
    # Source: RelayRdpByExtension.toml
    RelayExt_RDP = @('.rdp')
    # Source: RelayInfraConfigByExtension.toml (for network device cred patterns)
    RelayExt_Infra = @('.xml','.json','.config','.ini','.inf','.cnf','.conf','.txt')

    # ========================================================
    # CONTENT REGEX RULES (applied to files matching relay extensions)
    # ========================================================

    # --- Generic (applied to ALL relay extensions) ---
    # Source: KeepPassOrKeyInCode.toml â€” Triage=Red
    Content_Red_PassOrKey = @(
        "passw?o?r?d\s*=\s*['""][^'""]{4}"
        "api[Kk]ey\s*=\s*['""][^'""]{4}"
        'passw?o?r?d?>\s*[^\s<]+\s*<'
        'passw?o?r?d?>.{3,2000}</pass'
        '[\s]\s*-passw?o?r?d?'
        'api[kK]ey>\s*[^\s<]+\s*<'
        "[_\-\.]oauth\s*=\s*['""][^'""]{4}"
        'client_secret\s*=*\s*'
        '<ExtendedMatchKey>ClientAuth'
        'GIUserPassword'
    )
    # Source: KeepAwsKeysInCode.toml â€” Triage=Red
    Content_Red_AWS = @(
        'aws[_\-\.]?key'
        "(\s|'|""|^|=)(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z2-7]{12,16}(\s|'|""|`$)"
    )
    # Source: KeepInlinePrivateKey.toml â€” Triage=Red
    Content_Red_PrivKey = @(
        '-----BEGIN( RSA| OPENSSH| DSA| EC| PGP)? PRIVATE KEY( BLOCK)?-----'
    )
    # Source: KeepSlackTokensInCode.toml â€” Triage=Red
    Content_Red_Slack = @(
        '(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'
        'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'
    )
    # Source: KeepSqlAccountCreation.toml â€” Triage=Red
    Content_Red_SQLAcct = @(
        'CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)'
    )
    # Source: KeepDbConnStringPw.toml â€” Triage=Yellow
    Content_Yellow_ConnStr = @(
        'connectionstring.{1,200}passw'
    )
    # Source: KeepS3UriPrefixInCode.toml â€” Triage=Yellow
    Content_Yellow_S3 = @(
        's3[a]?://[a-zA-Z0-9\-\+/]{2,16}'
    )

    # --- CMD/Batch specific ---
    # Source: KeepCmdCredentials.toml â€” Triage=Red
    Content_Red_Cmd = @(
        "passwo?r?d\s*=\s*['""][^'""]{4}"
        'schtasks.{1,300}(/rp\s|/p\s)'
        'net user '
        'psexec .{0,100} -p '
        'net use .{0,300} /user:'
        'cmdkey '
    )
    # --- PowerShell specific ---
    # Source: KeepPsCredentials.toml â€” Triage=Red
    Content_Red_PS = @(
        '-SecureString'
        '-AsPlainText'
        '\[Net\.NetworkCredential\]::new\('
    )
    # --- C# / ASP.NET specific ---
    # Source: KeepCSharpViewstateKeys.toml â€” Triage=Red
    Content_Red_CSharp = @(
        "validationkey\s*=\s*['""][^'""]{4}"
        "decryptionkey\s*=\s*['""][^'""]{4}"
    )
    # Source: KeepCSharpDbConnStringsRed.toml â€” Triage=Red
    Content_Red_CSharpDB = @(
        'Data Source=.+(;|)Password=.+(;|)'
        'Password=.+(;|)Data Source=.+(;|)'
    )
    # Source: KeepCSharpDbConnStringsYellow.toml â€” Triage=Yellow
    Content_Yellow_CSharpDB = @(
        'Data Source=.+Integrated Security=(SSPI|true)'
        'Integrated Security=(SSPI|true);.*Data Source=.+'
    )
    # --- Java specific ---
    # Source: KeepJavaDbConnStrings.toml â€” Triage=Red
    Content_Red_Java = @(
        '\.getConnection\("jdbc\:'
        "passwo?r?d\s*=\s*['""][^'""]{4}"
    )
    # --- PHP specific ---
    # Source: KeepPhpDbConnStrings.toml â€” Triage=Red
    Content_Red_PHP = @(
        'mysql_connect\s*\(.*\$.*\)'
        'mysql_pconnect\s*\(.*\$.*\)'
        'mysql_change_user\s*\(.*\$.*\)'
        'pg_connect\s*\(.*\$.*\)'
        'pg_pconnect\s*\(.*\$.*\)'
    )
    # --- Python specific ---
    # Source: KeepPyDbConnStrings.toml â€” Triage=Red
    Content_Red_Python = @(
        'mysql\.connector\.connect\('
        'psycopg2\.connect\('
    )
    # --- Ruby specific ---
    # Source: KeepRubyDbConnStrings.toml â€” Triage=Red
    Content_Red_Ruby = @('DBI\.connect\(')
    # --- Perl specific ---
    # Source: KeepPerlDbConnStrings.toml â€” Triage=Red
    Content_Red_Perl = @('DBI\-\>connect\(')
    # --- Network device configs ---
    # Source: KeepNetConfigCreds.toml â€” Triage=Red
    Content_Red_NetConfig = @(
        'NVRAM config last updated',
        'enable password \.',
        'simple-bind authenticated encrypt',
        'pac key [0-7] ',
        'snmp-server community\s.+\sRW'
    )
    # --- RDP password ---
    # Source: KeepRdpPasswords.toml â€” Triage=Red
    Content_Red_RDP = @('password 51\:b')
    # --- Unattend.xml ---
    # Source: KeepUnattendXmlRegexRed.toml â€” Triage=Red
    Content_Red_Unattend = @(
        '(?s)<AdministratorPassword>.{0,30}<Value>.*<\/Value>',
        '(?s)<AutoLogon>.{0,30}<Value>.*<\/Value>'
    )
    # --- Firefox logins.json ---
    # Source: KeepFfLoginsJsonRelay.toml â€” Triage=Red
    Content_Red_Firefox = @(
        '"encryptedPassword":"[A-Za-z0-9+/=]+"'
    )

    # ========================================================
    # PATH-BASED RULES
    # ========================================================
    # Source: KeepSSHFilesByPath.toml â€” Triage=Black
    Path_Black_SSH = '\.ssh\\'
    # Source: KeepCloudApiKeysByPath.toml â€” Triage=Black
    Path_Black_Cloud = @('\.aws\\','doctl\\config.yaml')
    # Source: KeepDomainJoinCredsByPath.toml â€” Triage=Red
    Path_Red_MDT = 'control\\customsettings.ini'
    # Source: KeepSCCMBootVarCredsByPath.toml â€” Triage=Red (regex)
    Path_Red_SCCM = @('REMINST\\SMSTemp\\.*\.var','SMS\\data\\Variables\.dat','SMS\\data\\Policy\.xml')
    # Source: unsorted.txt KeepPathContainsRed â€” Triage=Red
    Path_Red_Unsorted = @('.purple\\accounts.xml','.gem\\credentials','config\\hub')

    # ========================================================
    # GERMAN FILENAME PATTERNS (optional)
    # ========================================================
    # Source: german-file-name-patterns.toml â€” Triage=Red
    German_Red = @('(Kenn|Pass)w[oÃ¶]rte?r?','SchlÃ¼ssel','Zug[aÃ¤]ng[es]?',
        'T[oÃ¼]r[ -]?Code','PINs?\.','Kont(o|en)','Logindaten','Anmeld(edaten|ung)')
}

# --- Worker scriptblock (Start-Job inherits caller's Kerberos/SMB auth) ---
$workerScript = {
    param([string]$HostName, $Rules, [int]$MaxSizeToGrep, [int]$MaxDepth, [bool]$EnableGerman)

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    function New-Finding {
        param($FilePath, $SharePath, $HostName, $Rule, $Triage, $FileSize, $Modified)
        return [PSCustomObject]@{
            Time     = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
            Host     = $HostName
            Share    = $SharePath
            Path     = $FilePath
            Rule     = $Rule
            Triage   = $Triage
            Size     = $FileSize
            Modified = $Modified
        }
    }

    function Test-DiscardPath {
        param($FilePath, $Rules)
        foreach ($dp in $Rules.DiscardPath) {
            if ($FilePath -like "*$dp*") { return $true }
        }
        foreach ($rp in $Rules.DiscardPathRegex) {
            if ($FilePath -match $rp) { return $true }
        }
        return $false
    }

    function Test-PostMatchDiscard {
        param($FileName, $FilePath, $Rules)
        $nameLower = $FileName.ToLower()
        foreach ($n in $Rules.DiscardPostMatchName) {
            if ($nameLower -eq $n.ToLower()) { return $true }
        }
        foreach ($p in $Rules.DiscardPostMatchPath) {
            if ($FilePath -like "*$p*") { return $true }
        }
        return $false
    }

    function Get-ContentFindings {
        param($FilePath, $Ext, $FileName, $SharePath, $HostName, $FileSize, $Modified, $Rules, $MaxSize)

        $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
        if ($FileSize -le 0 -or $FileSize -gt $MaxSize) { return $findings }

        # Determine which content rules to apply based on extension
        $contentChecks = @()

        # All relay extensions get the generic rules
        $allRelayExts = $Rules.RelayExt_Config + $Rules.RelayExt_PS + $Rules.RelayExt_Cmd +
            $Rules.RelayExt_CSharp + $Rules.RelayExt_Java + $Rules.RelayExt_JS +
            $Rules.RelayExt_Python + $Rules.RelayExt_PHP + $Rules.RelayExt_Perl +
            $Rules.RelayExt_Ruby + $Rules.RelayExt_VBS + $Rules.RelayExt_Shell +
            $Rules.RelayExt_RDP + $Rules.RelayExt_Infra
        $allRelayExts = $allRelayExts | Select-Object -Unique

        if ($allRelayExts -notcontains $Ext) { return $findings }

        # Generic rules (all relay extensions)
        $contentChecks += @{Patterns=$Rules.Content_Red_PassOrKey; Triage='Red'; Name='PassOrKeyInCode'}
        $contentChecks += @{Patterns=$Rules.Content_Red_AWS; Triage='Red'; Name='AwsKeysInCode'}
        $contentChecks += @{Patterns=$Rules.Content_Red_PrivKey; Triage='Red'; Name='InlinePrivateKey'}
        $contentChecks += @{Patterns=$Rules.Content_Red_Slack; Triage='Red'; Name='SlackTokensInCode'}
        $contentChecks += @{Patterns=$Rules.Content_Red_SQLAcct; Triage='Red'; Name='SqlAccountCreation'}
        $contentChecks += @{Patterns=$Rules.Content_Yellow_ConnStr; Triage='Yellow'; Name='DbConnStringPw'}
        $contentChecks += @{Patterns=$Rules.Content_Yellow_S3; Triage='Yellow'; Name='S3UriPrefix'}

        # Language-specific rules
        if ($Rules.RelayExt_Cmd -contains $Ext -or $Rules.RelayExt_VBS -contains $Ext) {
            $contentChecks += @{Patterns=$Rules.Content_Red_Cmd; Triage='Red'; Name='CmdCredentials'}
        }
        if ($Rules.RelayExt_PS -contains $Ext) {
            $contentChecks += @{Patterns=$Rules.Content_Red_PS; Triage='Red'; Name='PsCredentials'}
            $contentChecks += @{Patterns=$Rules.Content_Red_Cmd; Triage='Red'; Name='CmdCredentials'}
        }
        if ($Rules.RelayExt_CSharp -contains $Ext) {
            $contentChecks += @{Patterns=$Rules.Content_Red_CSharp; Triage='Red'; Name='CSharpViewstateKeys'}
            $contentChecks += @{Patterns=$Rules.Content_Red_CSharpDB; Triage='Red'; Name='CSharpDbConnStrRed'}
            $contentChecks += @{Patterns=$Rules.Content_Yellow_CSharpDB; Triage='Yellow'; Name='CSharpDbConnStrYellow'}
        }
        if ($Rules.RelayExt_Java -contains $Ext) {
            $contentChecks += @{Patterns=$Rules.Content_Red_Java; Triage='Red'; Name='JavaDbConnStrings'}
        }
        if ($Rules.RelayExt_PHP -contains $Ext) {
            $contentChecks += @{Patterns=$Rules.Content_Red_PHP; Triage='Red'; Name='PhpDbConnStrings'}
        }
        if ($Rules.RelayExt_Python -contains $Ext) {
            $contentChecks += @{Patterns=$Rules.Content_Red_Python; Triage='Red'; Name='PyDbConnStrings'}
        }
        if ($Rules.RelayExt_Ruby -contains $Ext) {
            $contentChecks += @{Patterns=$Rules.Content_Red_Ruby; Triage='Red'; Name='RubyDbConnStrings'}
        }
        if ($Rules.RelayExt_Perl -contains $Ext) {
            $contentChecks += @{Patterns=$Rules.Content_Red_Perl; Triage='Red'; Name='PerlDbConnStrings'}
        }
        if ($Rules.RelayExt_Infra -contains $Ext) {
            $contentChecks += @{Patterns=$Rules.Content_Red_NetConfig; Triage='Red'; Name='NetConfigCreds'}
        }
        if ($Rules.RelayExt_RDP -contains $Ext) {
            $contentChecks += @{Patterns=$Rules.Content_Red_RDP; Triage='Red'; Name='RdpPasswords'}
        }

        # Unattend.xml special handling
        $nameLower = $FileName.ToLower()
        if ($nameLower -eq 'unattend.xml' -or $nameLower -eq 'autounattend.xml') {
            $contentChecks += @{Patterns=$Rules.Content_Red_Unattend; Triage='Red'; Name='UnattendXmlCreds'}
        }
        # Firefox logins.json
        if ($nameLower -eq 'logins.json') {
            $contentChecks += @{Patterns=$Rules.Content_Red_Firefox; Triage='Red'; Name='FirefoxEncryptedPw'}
        }

        try {
            $content = [System.IO.File]::ReadAllText($FilePath)
            foreach ($check in $contentChecks) {
                foreach ($pattern in $check.Patterns) {
                    if ($content -match $pattern) {
                        $m = $Matches[0]
                        if ($m.Length -gt 200) { $m = $m.Substring(0, 200) + '...' }
                        $findings.Add((New-Finding -FilePath $FilePath -SharePath $SharePath `
                            -HostName $HostName -Rule "$($check.Name)[$pattern] -> $m" `
                            -Triage $check.Triage -FileSize $FileSize -Modified $Modified))
                        break
                    }
                }
            }
        } catch {}

        return $findings
    }

    function Classify-File {
        param($Item, $SharePath, $HostName, $Rules, $MaxSize, $EnableGerman)

        $fileName = $Item.Name
        $filePath = $Item.FullName
        $fileSize = $Item.Length
        $modified = $Item.LastWriteTime
        $nameLower = $fileName.ToLower()
        $ext = [System.IO.Path]::GetExtension($nameLower)

        # --- DISCARD checks ---
        if ($Rules.DiscardExtension -contains $ext) { return $null }
        if ($Rules.DiscardFileName -contains $nameLower) { return $null }
        if (Test-DiscardPath -FilePath $filePath -Rules $Rules) { return $null }

        $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
        $mkFinding = { param($Rule,$Triage)
            New-Finding -FilePath $filePath -SharePath $SharePath -HostName $HostName `
                -Rule $Rule -Triage $Triage -FileSize $fileSize -Modified $modified
        }

        # ========== EXACT FILENAME â€” BLACK ==========
        $blackNames = $Rules.ExactName_Black_SSH + $Rules.ExactName_Black_WinHash +
            $Rules.ExactName_Black_NixHash + $Rules.ExactName_Black_NetConfig +
            $Rules.ExactName_Black_MemDump + $Rules.ExactName_Black_CyberArk +
            $Rules.ExactName_Black_RemoteAccess + $Rules.ExactName_Black_CloudApi
        foreach ($bn in $blackNames) {
            if ($nameLower -eq $bn.ToLower()) {
                $findings.Add((& $mkFinding "ExactName_Black[$bn]" 'Black'))
                break
            }
        }

        # ========== EXACT FILENAME â€” RED ==========
        $redNames = $Rules.ExactName_Red_Config + $Rules.ExactName_Red_PHP +
            $Rules.ExactName_Red_Ruby + $Rules.ExactName_Red_PassFiles +
            $Rules.ExactName_Red_FTP + $Rules.ExactName_Red_FTPClient +
            $Rules.ExactName_Red_Jenkins + $Rules.ExactName_Red_DBMgt +
            $Rules.ExactName_Red_Git
        foreach ($rn in $redNames) {
            if ($nameLower -eq $rn.ToLower()) {
                $findings.Add((& $mkFinding "ExactName_Red[$rn]" 'Red'))
                break
            }
        }

        # ========== EXACT FILENAME â€” YELLOW ==========
        $yellowNames = $Rules.ExactName_Yellow_MDT + $Rules.ExactName_Yellow_Defender
        foreach ($yn in $yellowNames) {
            if ($nameLower -eq $yn.ToLower()) {
                $findings.Add((& $mkFinding "ExactName_Yellow[$yn]" 'Yellow'))
                break
            }
        }

        # ========== EXACT FILENAME â€” GREEN ==========
        $greenNames = $Rules.ExactName_Green_History + $Rules.ExactName_Green_RC +
            $Rules.ExactName_Green_Unsorted
        foreach ($gn in $greenNames) {
            if ($nameLower -eq $gn.ToLower()) {
                $findings.Add((& $mkFinding "ExactName_Green[$gn]" 'Green'))
                break
            }
        }

        # ========== EXTENSION â€” BLACK ==========
        $blackExts = $Rules.Ext_Black_PassMgr + $Rules.Ext_Black_SSH
        if ($blackExts -contains $ext) {
            $findings.Add((& $mkFinding "Extension_Black[$ext]" 'Black'))
        }

        # ========== EXTENSION â€” RED ==========
        $redExts = $Rules.Ext_Red_Cert + $Rules.Ext_Red_IAC + $Rules.Ext_Red_VMDisk +
            $Rules.Ext_Red_MemDump + $Rules.Ext_Red_CyberArk
        if ($redExts -contains $ext) {
            $findings.Add((& $mkFinding "Extension_Red[$ext]" 'Red'))
        }

        # ========== EXTENSION â€” YELLOW ==========
        $yellowExts = $Rules.Ext_Yellow_DB + $Rules.Ext_Yellow_Kerberos +
            $Rules.Ext_Yellow_Pcap + $Rules.Ext_Yellow_RemoteAccess + $Rules.Ext_Yellow_Deploy +
            $Rules.Ext_Yellow_Keys
        if ($yellowExts -contains $ext) {
            $findings.Add((& $mkFinding "Extension_Yellow[$ext]" 'Yellow'))
        }

        # ========== FILENAME CONTAINS â€” GREEN ==========
        foreach ($nc in $Rules.NameContains_Green) {
            if ($nameLower -like "*$($nc.ToLower())*") {
                $findings.Add((& $mkFinding "NameContains_Green[$nc]" 'Green'))
                break
            }
        }

        # ========== FILENAME ENDSWITH â€” relay to content scan ==========
        foreach ($es in $Rules.NameEndsWith_PrivKey) {
            if ($nameLower.EndsWith($es.ToLower())) {
                $findings.Add((& $mkFinding "NameEndsWith_PrivKey[$es]" 'Green'))
                break
            }
        }

        # ========== FILENAME REGEX â€” YELLOW ==========
        foreach ($rx in $Rules.NameRegex_Yellow_Kerberos) {
            if ($nameLower -match $rx) {
                $findings.Add((& $mkFinding "NameRegex_Yellow[$rx]" 'Yellow'))
                break
            }
        }

        # ========== PATH-BASED â€” BLACK ==========
        if ($filePath -match [regex]::Escape($Rules.Path_Black_SSH)) {
            $findings.Add((& $mkFinding "Path_Black[.ssh]" 'Black'))
        }
        foreach ($cp in $Rules.Path_Black_Cloud) {
            if ($filePath -like "*$cp*") {
                $findings.Add((& $mkFinding "Path_Black_Cloud[$cp]" 'Black'))
                break
            }
        }

        # ========== PATH-BASED â€” RED ==========
        if ($filePath -like "*$($Rules.Path_Red_MDT)*") {
            $findings.Add((& $mkFinding "Path_Red_MDT" 'Red'))
        }
        foreach ($sp in $Rules.Path_Red_SCCM) {
            if ($filePath -match $sp) {
                $findings.Add((& $mkFinding "Path_Red_SCCM[$sp]" 'Red'))
                break
            }
        }
        foreach ($up in $Rules.Path_Red_Unsorted) {
            if ($filePath -like "*$up*") {
                $findings.Add((& $mkFinding "Path_Red[$up]" 'Red'))
                break
            }
        }

        # ========== GERMAN FILENAME PATTERNS â€” RED ==========
        if ($EnableGerman) {
            foreach ($gp in $Rules.German_Red) {
                if ($fileName -match $gp) {
                    $findings.Add((& $mkFinding "German_Red[$gp]" 'Red'))
                    break
                }
            }
        }

        # ========== CONTENT SCANNING ==========
        $contentFindings = Get-ContentFindings -FilePath $filePath -Ext $ext -FileName $fileName `
            -SharePath $SharePath -HostName $HostName -FileSize $fileSize -Modified $modified `
            -Rules $Rules -MaxSize $MaxSize
        if ($contentFindings.Count -gt 0) {
            foreach ($cf in $contentFindings) { $findings.Add($cf) }
        }

        # ========== POST-MATCH DISCARD ==========
        if ($findings.Count -gt 0 -and (Test-PostMatchDiscard -FileName $fileName -FilePath $filePath -Rules $Rules)) {
            return $null
        }

        # Return highest severity finding only
        if ($findings.Count -gt 0) {
            $sevOrder = @{ 'Black'=0; 'Red'=1; 'Yellow'=2; 'Green'=3 }
            return ($findings | Sort-Object { $sevOrder[$_.Triage] } | Select-Object -First 1)
        }
        return $null
    }

    # --- Enumerate shares via net view ---
    $shares = @()
    $netviewRaw = @()
    try {
        $netviewRaw = @(net view "\\$HostName" /all 2>&1)
        foreach ($line in $netviewRaw) {
            if ($line -match '^\s*(.+?)\s+(Disk|Platte)\s') {
                $shareName = $Matches[1].Trim()
                if ($shareName -notmatch '(IPC|print)\$$') {
                    $shares += $shareName
                }
            }
        }
    } catch {}

    # Report readable C$/ADMIN$ as Black (like Snaffler KeepDollarShares)
    foreach ($ds in @('C$','ADMIN$')) {
        $testPath = "\\$HostName\$ds"
        try {
            if ([System.IO.Directory]::Exists($testPath)) {
                $results.Add((New-Finding -FilePath $testPath -SharePath $testPath `
                    -HostName $HostName -Rule "ReadableDollarShare[$ds]" `
                    -Triage 'Black' -FileSize 0 -Modified $null))
            }
        } catch {}
    }

    # Report SCCMContentLib$ as Yellow (like Snaffler KeepSCCMShares)
    try {
        $sccmPath = "\\$HostName\SCCMContentLib`$"
        if ([System.IO.Directory]::Exists($sccmPath)) {
            $results.Add((New-Finding -FilePath $sccmPath -SharePath $sccmPath `
                -HostName $HostName -Rule "ReadableSCCMShare" `
                -Triage 'Yellow' -FileSize 0 -Modified $null))
        }
    } catch {}

    if ($shares.Count -eq 0) {
        $debugMsg = "NetViewLines=$($netviewRaw.Count)"
        if ($netviewRaw.Count -gt 0) { $debugMsg += "; First=$($netviewRaw[0])" }
        return @((New-Finding -FilePath 'N/A' -SharePath 'N/A' `
            -HostName $HostName -Rule "NoSharesFound($debugMsg)" -Triage 'Info' -FileSize 0 -Modified $null))
    }

    $totalFiles = 0
    $totalDiscarded = 0
    foreach ($share in $shares) {
        $uncPath = "\\$HostName\$share"
        try {
            Get-ChildItem -LiteralPath $uncPath -Recurse -File -Depth $MaxDepth -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $totalFiles++
                    $finding = Classify-File -Item $_ -SharePath $uncPath -HostName $HostName `
                        -Rules $Rules -MaxSize $MaxSizeToGrep -EnableGerman $EnableGerman
                    if ($finding) { $results.Add($finding) }
                    else { $totalDiscarded++ }
                }
        } catch {}
    }

    if ($results.Count -eq 0) {
        $shareList = $shares -join ','
        return @((New-Finding -FilePath 'No findings' -SharePath 'scanned' `
            -HostName $HostName -Rule "Clean(shares=$shareList;files=$totalFiles;discarded=$totalDiscarded)" `
            -Triage 'Info' -FileSize 0 -Modified $null))
    }

    return $results.ToArray()
}

# --- Write CSV header ---
$headerLine = '"Time","Host","Share","Path","Rule","Triage","Size","Modified"'
[System.IO.File]::WriteAllText($outfile, $headerLine + [Environment]::NewLine, [System.Text.Encoding]::UTF8)
Write-Host "[*] Output file created: $outfile"
Write-Host ""

# --- Throttled Start-Job (inherits Kerberos/SMB auth, N concurrent) ---
$findingCount = 0
$completed = 0
$hostQueue = [System.Collections.Queue]::new()
foreach ($h in $hosts) { $hostQueue.Enqueue($h) }
$runningJobs = [System.Collections.Generic.List[PSCustomObject]]::new()

function Collect-Finished {
    param($runningJobs, $outfile, [ref]$findingCount, [ref]$completed, $totalHosts)
    $doneIdx = @()
    for ($j = 0; $j -lt $runningJobs.Count; $j++) {
        if ($runningJobs[$j].Job.State -in @('Completed','Failed','Stopped')) {
            $doneIdx += $j
        }
    }
    foreach ($j in ($doneIdx | Sort-Object -Descending)) {
        $entry = $runningJobs[$j]
        try {
            $output = Receive-Job -Job $entry.Job -ErrorAction SilentlyContinue
            foreach ($item in $output) {
                if (-not $item) { continue }
                $hasHost = $false
                try { $hasHost = [bool]$item.Host } catch {}
                if (-not $hasHost) { continue }
                if ($item.Triage -ne 'Info') {
                    $findingCount.Value++
                    $csvLine = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}"' -f `
                        $item.Time, $item.Host, $item.Share, `
                        ($item.Path -replace '"','""'), ($item.Rule -replace '"','""'), `
                        $item.Triage, $item.Size, $item.Modified
                    [System.IO.File]::AppendAllText($outfile, $csvLine + [Environment]::NewLine, [System.Text.Encoding]::UTF8)
                }
                if ($item.Triage -eq 'Black') {
                    Write-Host "  [!!] BLACK  $($item.Host) | $($item.Path) | $($item.Rule)" -ForegroundColor Red -BackgroundColor Black
                } elseif ($item.Triage -eq 'Red') {
                    Write-Host "  [!]  RED    $($item.Host) | $($item.Path) | $($item.Rule)" -ForegroundColor Red
                } elseif ($item.Triage -eq 'Yellow') {
                    Write-Host "  [~]  YELLOW $($item.Host) | $($item.Path) | $($item.Rule)" -ForegroundColor Yellow
                } elseif ($item.Triage -eq 'Green') {
                    Write-Host "  [.]  GREEN  $($item.Host) | $($item.Path) | $($item.Rule)" -ForegroundColor Green
                } elseif ($item.Triage -eq 'Info') {
                    Write-Host "  [i]  $($item.Host) | $($item.Rule)" -ForegroundColor DarkGray
                }
            }
        } catch {
            Write-Host "  [x] Error from $($entry.Host): $_" -ForegroundColor Red
        }
        Remove-Job -Job $entry.Job -Force -ErrorAction SilentlyContinue
        $completed.Value++
        Write-Host "[*] $($completed.Value)/$totalHosts done | $($findingCount.Value) findings | $($entry.Host)" -ForegroundColor DarkCyan
        $runningJobs.RemoveAt($j)
    }
}

while ($hostQueue.Count -gt 0 -or $runningJobs.Count -gt 0) {
    # Launch new jobs up to thread limit
    while ($hostQueue.Count -gt 0 -and $runningJobs.Count -lt $threads) {
        $h = $hostQueue.Dequeue()
        $job = Start-Job -ScriptBlock $workerScript -ArgumentList $h, $rules, $maxsizetogrep, $depth, ([bool]$german)
        $runningJobs.Add([PSCustomObject]@{ Host = $h; Job = $job })
        Write-Host "[>] Started: $h ($($runningJobs.Count) active)" -ForegroundColor Cyan
    }
    # Collect finished jobs
    Collect-Finished -runningJobs $runningJobs -outfile $outfile `
        -findingCount ([ref]$findingCount) -completed ([ref]$completed) -totalHosts $hosts.Count
    # Brief pause before next poll
    if ($runningJobs.Count -gt 0) { Start-Sleep -Milliseconds 500 }
}

if ($findingCount -eq 0) {
    Write-Host ""
    Write-Host "[-] No findings." -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "[+] $findingCount findings written to $outfile" -ForegroundColor Green
}

# --- Summary ---
Write-Host ""
Write-Host "=== SUMMARY ===" -ForegroundColor White
Write-Host "    Hosts scanned: $($hosts.Count)" -ForegroundColor White
Write-Host "    Total findings: $findingCount" -ForegroundColor White
Write-Host ""
Write-Host "I snaffled 'til the snafflin was done." -ForegroundColor Magenta

} # end Invoke-Snaffle
