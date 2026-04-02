rule vidar_rule : Vidar dll {
    meta:
        description = "Detects the presence of a Vidar information stealer binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $hex_string = {4D 5A} // "MZ" header of PE files
        $string1 = "Stop reversing the binary"
        $string2 = "Reconsider your life choices"
        $string3 = "And go touch some grass"
        $string4 = "C:\\tgbotsideloading\\sideload\\x64\\AdvancedPolymorph.h"
    condition:
       $hex_string and $string4 and ($string1 or $string2 or $string3)
}
