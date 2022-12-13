function Get-YaraMatches {
<#
.SYNOPSIS
Compiles and runs yara signatures against specified files.

.DESCRIPTION
Compiles and runs yara signatures against the specified files and then parses
the results into objects which are returned via the pipeline.

.EXAMPLE
$results = Get-YaraMatches -File "C:\malware\027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745.bin"
$results[0] | fl *

Blacklist : 0.23927378
Rule      : rule Str_Win32_Winsock2_Library
            {

                meta:
                    author = "@adricnet"
                    description = "Match Winsock 2 API library declaration"
                    method = "String match"

                strings:
                    $ws2_lib = "Ws2_32.dll" nocase
                    $wsock2_lib = "WSock32.dll" nocase

                condition:
                (any of ($ws2_lib, $wsock2_lib))
            }
Ruleset   : APT Set 1
InfoGain  : 0.025520794
RuleName  : Str_Win32_Winsock2_Library
Whitelist : 0.093833934
File      : C:\malware\027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745.bin

.EXAMPLE
$results = Get-YaraMatches -File "C:\malware\027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745.bin"
$results | Select Ruleset,RuleName,Whitelist,Blacklist,InfoGain | ft -a

Ruleset      RuleName                                     Whitelist   Blacklist   InfoGain
-------      --------                                     ---------   ---------   --------
APT Set 1    Str_Win32_Winsock2_Library                   0.093833934 0.23927378  0.025520794
APT Set 1    DoublePulsarXor_Petya                        0           5.56917E-06 2.33072E-06
APT Set 1    DoublePulsarDllInjection_Petya               0           5.56917E-06 2.33072E-06
APT Set 1    ransomware_PetrWrap                          0           5.56917E-06 2.33072E-06
APT Set 1    FE_CPE_MS17_010_RANSOMWARE                   0           5.56917E-06 2.33072E-06
APT Set 1    petya_eternalblue                            0           5.56917E-06 2.33072E-06
Capabilities escalate_priv                                0.106307529 0.17767877  0.006953452
Capabilities cred_local                                   0.010131809 0.04436957  0.007570034
Capabilities win_token                                    0.196012273 0.219993317 0.000583858
Capabilities win_files_operation                          0.335267298 0.504912007 0.01984064
Crypto       CRC32_poly_Constant                          0.106489137 0.223229004 0.016504966
Crypto       CRC32_table                                  0.058993892 0.082930497 0.001445101
Open Source  IsPeFile                                     0           0           0
Open Source  sysinternals_not_signed                      0.000946273 0.000517933 4.38599E-05
Open Source  Generic_bitmask_table__32_lil_128_           0.003192476 0.000562486 0.000734221
Open Source  Windows_CryptAcquireContext__8_byt_STR_21_   0.012970627 0.008387169 0.000342743
Open Source  bitmask__32_lil_128_                         0.003154242 0.000562486 0.000719289
Open Source  Windows_CryptImportKey__8_byt_STR_15_        0.009424494 0.010091334 7.70059E-06
Open Source  PEiD_00071_Anti007____NsPacK_Private_        0.011947888 0.034924259 0.003873335
Open Source  PEiD_02191_tElock_0_99___1_0_private____tE__ 0.050028197 0.064435286 0.000640483
Open Source  misc_pe_signature                            0           0           0
Open Source  RansomImportDetect                           0           0           0
Open Source  DebuggerTiming__Ticks                        0.302300685 0.205613722 0.008413969
Open Source  research_pe_signed_outside_timestamp         0           0           0
Open Source  create_process                               0.195945365 0.225662731 0.000887301
Open Source  Win32_Ransomware_NotPetya                    0           5.56917E-06 2.33072E-06
Open Source  BadRabbit_Gen                                0           1.11383E-05 4.66145E-06
Open Source  NotPetya_Ransomware_Jun17                    0           5.56917E-06 2.33072E-06
Open Source  VBox_Detection                               0.00571587  0.006939185 3.96658E-05
Open Source  IsPE32                                       0           0           0
Open Source  IsDLL                                        0           0           0
Open Source  IsConsole                                    0           0           0
Open Source  IsPacked                                     0           0           0
Open Source  HasOverlay                                   0           0           0
Open Source  HasDigitalSignature                          0.250810067 0.082295611 0.037138875
Open Source  HasRichSignature                             0.361533535 0.304449766 0.002473488
Open Source  DLL_inject                                   0.094436107 0.134790599 0.002669484
PEID         Microsoft_Visual_Cpp_v50v60_MFC              0.071352788 0.242531744 0.037452384
#>
    param(
        [Parameter(ParameterSetName = "String", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateScript({Test-Path $_})]
        [string]$File,

        [Parameter(ParameterSetName = "FileInfo", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [System.IO.FileInfo]$FileInfo,

        [Parameter(Mandatory = $false)]
        [ValidateScript({Test-Path $_})]
        [string]$RuleDirectory = "$PSScriptRoot\..\yara-rules\",

        [Parameter(Mandatory = $false)]
        [string]$CompiledRules = "$PSScriptRoot\..\yara-rules\compiled.bin",

        [Parameter(Mandatory = $false)]
        [string]$MapPath = "$PSScriptRoot\..\lookups\map.csv",

        [Parameter(Mandatory = $false)]
        [string]$StatisticsPath = "$PSScriptRoot\..\lookups\statistics.csv",
        
        [Parameter(Mandatory = $false)]
        [ValidateScript({Test-Path $_})]
        [string]$YaraPath = "$PSScriptRoot\..\tools\yara\yara64.exe",

        [Parameter(Mandatory = $false)]
        [ValidateScript({Test-Path $_})]
        [string]$YaraCPath = "$PSScriptRoot\..\tools\yara\yarac64.exe"
    )

    BEGIN {
        #If compiled rules do not exist, compile them and save the result
        if(!(Test-Path $CompiledRules)) {
            $rules = Get-ChildItem -Path $RuleDirectory -Recurse -File -Filter "*.txt" | % { "`"$($_.FullName)`"" }
            & $YaraCPath -w $rules $CompiledRules
        }
		
		#Load a map of the signatures
        $map = Import-Csv $MapPath
        $table = New-Object System.Collections.Hashtable([System.StringComparer]::InvariantCultureIgnoreCase);
        foreach($item in $map) {
            $table.Add($item.Name, $item);
        }

        #Load the statistics for the signatures
        $map = Import-Csv $StatisticsPath
        $stats = New-Object System.Collections.Hashtable([System.StringComparer]::InvariantCultureIgnoreCase);
        foreach($item in $map) {
            if(!$stats.Contains($item.name)) {
                $item.whitelist = [int]$item.whitelist;
                $item.blacklist = [int]$item.blacklist;
                $item.sum = [int]$item.sum;
                $item.remainder = [int]$item.remainder
                $item.wpercentage = [float]::Parse($item.wpercentage);
                $item.bpercentage = [float]::Parse($item.bpercentage);
                $item.wnorm = [float]::Parse($item.wnorm);
                $item.bnorm = [float]::Parse($item.bnorm);
                $item.wrnorm = [float]::Parse($item.wrnorm);
                $item.wbnorm = [float]::Parse($item.wbnorm);
                $item.tentropy = [float]::Parse($item.tentropy);
                $item.centropy = [float]::Parse($item.centropy);
                $item.gain = [float]::Parse($item.gain);

                $stats.Add($item.name, $item);
            }
        }
    }

    PROCESS {
        #Determine the path to the file based off of the type of input
        $path = $null;
        if($PSCmdlet.ParameterSetName -eq "String") {
            $path = $File;
        } else {
            $path = $FileInfo.FullName;
        }
        
        #Execute Yara and store the results
        Write-Verbose "Executing: $YaraPath -w $rules $path";
        $results = & $YaraPath -w -C $CompiledRules $path;

        #Continue to the next pipelined input if there are no results
        if([String]::IsNullOrWhiteSpace($results)) {
            return;
        }

        #Parse the string output into usable objects
        foreach($line in $results.Split([Environment]::NewLine)) {
            $index = $line.IndexOf(' ');
            $file = $line.Substring($index + 1, $line.Length - $index - 1);
            $ruleName = $line.Substring(0, $index);

            $lookup = $table[$ruleName];
            if($lookup -ne $null) {
                $ruleset = $lookup.Ruleset;
                $rule = $lookup.Rule;
            } else {
                $ruleset = $null;
                $rule = $null;
            }

            $lookup = $stats[$ruleName]
            if($lookup -ne $null) {
                $whitelist = $lookup.wpercentage;
                $blacklist = $lookup.bpercentage;
                $infogain = $lookup.gain;
            } else {
                $whitelist = 0;
                $blacklist = 0;
                $infogain = 0;
            }

            New-Object PSObject -Property @{
                File = $file;
                RuleName = $ruleName;
                Ruleset = $ruleset;
                Whitelist = $whitelist;
                Blacklist = $blacklist;
                InfoGain = $infogain;
                Rule = $rule;
            }
        }
    }
}