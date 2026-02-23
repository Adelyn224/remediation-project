rule netWire_rule {
    meta:
        description = "Detects the presence of a NetWire binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $hext_string = {4D 5A} // "MZ" header of the PE file
        $string1 = "!This program cannot be run in DOS mode."
        $string2 = "http://www.yandex.com"
        $string3 = "winhttp.dll"
    condition:
        $hext_string and ($string1 or $string2 or $string3)
}
