rule vidar_rule {
    meta:
        description = "Detects the presence of a Vidar information stealer binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $hex_string = {4D 5A} // "MZ" header of PE files
        $hex_string2 = {2E 69 64 61 74 61} // ".idata"
        $hex_string3 = {2E 74 65 78 74} // ".text"
        $hex_string4 = {2E 72 73 72 63} // ".rsrc"
        $hex_string5 = {2E 64 61 74 61} // ".data"
        $hex_string6 = {2E 72 65 6C 6F 63} // ".reloc"
        $string1 = "!This program cannot be run in DOS mode."
        $string2 = "GetSystemInfo"
    condition:
       $hex_string or $hex_string2 or $hex_string3 or $hex_string4 or $hex_string5 or $hex_string6 or $string1 or $string2
}
