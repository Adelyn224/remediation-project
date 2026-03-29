rule massLogger_rule : MassLogger exe {
    meta:
        description = "Detects the presence of a credential stealer binary"
        author = "me"
        date = "14/02/2026"
        version = "1.0"
    strings:
        $hex_string1 = {4D 5A} // "MZ"
        $hex_string2 = {40 2E 72 65 6C 6F 63} // "@.reloc"
        $string1 = "This program cannot be run in DOS mode." 
        $string3 = "<AnalyzeNetworkSecurityLogs>b__0"
    condition:
        $string3 and $hex_string2 and ($hex_string1 or $string1)
}
