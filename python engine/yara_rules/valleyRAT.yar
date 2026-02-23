rule socks5Systemz_rule {
    meta:
        description = "Detects the presence of a Socks5 Systemz binary"
        author = "me"
        date = "21/02/2026" 
        version = "1.0" 
    strings:
        $hext_string1 = {4D 5A} // "MZ" header of the PE file
        $hex_string2 = {40 2E 78 64 61 74 61} // "@.xdata"
        $string1 = "!This program cannot be run in DOS mode."
    condition:
        ($hext_string1 or $string1) and $hex_string2
}
