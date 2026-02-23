rule coinMiner_rule {
    meta:
        description = "Detects the presence of a coin miner binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $hex_string1 = {4D 5A 78} // "MZx" header of the PE file
        $hex_string2 = {40 2E 43 52 54} // "@.CRT" section header
        $hex_string3 = {40 2E 74 6C 73} // "@.tls" section header
        $string1 = "connection: keep-alive"
        $string2 = "connection: close"
        $string3 = "!This program cannot be run in DOS mode."
        $string4 = "Panicked during a panic. Aborting."
        $string5 = "Unable to dump stack trace: debug info stripped"
    condition:
        ($hex_string1 or $hex_string2 or $hex_string3) and ($string1 or $string2 or $string3 or $string4 or $string5)
}
