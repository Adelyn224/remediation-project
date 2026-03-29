rule netWire_rule : NetWire exe RAT {
    meta:
        description = "Detects the presence of a NetWire binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $hex_string = {4D 5A} // "MZ" header of the PE file
        $string1 = "!This program cannot be run in DOS mode."
        $string2 = "winhttp.dll"
        $string3 = "MT_qUDrj\\F4Y0W6W85\\U4RSWg6\\PQ00dR5zd064WR\\rQR\\"
        $string4 = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
    condition:
        $string2 and $string3 and $string4 and ($hex_string or $string1)
}
