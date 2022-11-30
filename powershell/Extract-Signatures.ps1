function Extract-Signatures {

    BEGIN {
        $regexString = @"
(?:\s*)(?<rule>(?:rule\s+)(?<name>[a-zA-Z0-9_]+)(?:\s*)(?:\:(\s*[a-zA-Z0-9_]+)+\s*)?\{(?>\{(?<c>)|[^{""}]+|(?:[""](?:[^""\\]|\\.)*[""])|\}(?<-c>))*(?(c)(?!))\})
"@;

        $regex = New-Object System.Text.RegularExpressions.Regex($regexString, [System.Text.RegularExpressions.RegexOptions]::Compiled);

        $files = gci "$PSScriptRoot\..\yara-rules" -Filter "*.txt" -File;
        foreach($file in $files) {
            $text = [System.IO.File]::ReadAllText($file.FullName);
            $matches = $regex.Matches($text);
            foreach($match in $matches) {
                New-Object PSObject -Property @{
                    "Name" = $match.Groups["name"].Value;
                    "Rule" = $match.Groups["rule"].Value;
                    "Ruleset" = $file.BaseName;
                }
            }
        }
    }
}

Extract-Signatures | Select Ruleset,Name,Rule | Sort Name -Unique | Export-Csv "$PSScriptRoot\..\lookups\map.csv" -NoTypeInformation;