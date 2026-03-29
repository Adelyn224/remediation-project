rule socks5Systemz_rule : Socks5Systemz exe {
    meta:
        description = "Detects the presence of a Socks5 Systemz binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $hex_string = {4D 5A 50} // "MZP" header of the PE file
        $string1 = "This program must be run under Win32."
        $string2 = "Specifies the password to use"
        $string3 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcmdline"
    condition:
        $hex_string and ($string1 or $string2 or $string3)
}
