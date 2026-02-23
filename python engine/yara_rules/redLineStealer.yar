rule redLineStealer_rule {
    meta:
        description = "Detects the presence of a RedLine Stealer binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $hex_string = {4D 5A} // "MZ" header of the PE file
        $string1 = "!This program cannot be run in DOS mode."
        $string2 = "https://api.ip.sb/ip"
        $string3 = "For more detailed information please visit https://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline"
    condition:
        ($hex_string or $string1) and ($string2 or $string3)
}
