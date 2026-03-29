rule snakeKeyLogger_rule : SnakeKeyLogger exe {
    meta:
        description = "Detects the presence of a snakeKeyLogger information stealer binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $hex_string = {4D 5A} // "MZ" header of PE files
        $string1 = "!This program cannot be run in DOS mode."
        $string2 = "http://varders.kozow.com:8081,http://aborters.duckdns.org:8081,http://anotherarmy.dns.army:8081"
        $string3 = "https://reallyfreegeoip.org/xml/"
        $string4 = "http://checkip.dyndns.org/"
        $string5 = "https://api.telegram.org/bot"
        $string6 = "http://51.38.247.67:8081/_send_.php?L"
    condition:
        $string2 and $string3 and $string4 and $string5 and $string6 and ($string1 or $hex_string)
}
