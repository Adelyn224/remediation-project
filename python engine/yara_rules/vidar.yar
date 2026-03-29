rule vidar_rule : Vidar exe UPX {
    meta:
        description = "Detects the presence of a Vidar information stealer binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $hex_string = {4D 5A} // "MZ" header of PE files
        $hex_string1 = {2E 69 64 61 74 61} // ".idata"
        $string1 = "!This program cannot be run in DOS mode."
        $string2 = "GetSystemInfo"
    condition:
       $hex_string1 and $string2 and (hex_string or $string1)
}
