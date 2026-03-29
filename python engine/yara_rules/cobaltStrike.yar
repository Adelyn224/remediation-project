rule cobaltStrike_rule : CobaltStrike exe {
    meta:
        description = "Detects the presence of a Cobalt Strike binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $hex_string = {4D 5A} // "MZ" header of the PE file
        $string1 = "!This program cannot be run in DOS mode."
        $string2 = "f:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\src\\mfc\\auxdata.cpp"
        $string3 = "GetSystemTimeAsFileTime"
    condition:
        $hex_string and ($string2 or ($string1 and $string3))
}
