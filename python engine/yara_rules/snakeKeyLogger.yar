rule snakeKeyLogger_rule : snakeKeyLogger exe {
    meta:
        description = "Detects the presence of a snakeKeyLogger information stealer binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $string1 = "http://varders.kozow.com:8081,http://aborters.duckdns.org:8081,http://anotherarmy.dns.army:8081" ascii wide
        $string2 = "https://reallyfreegeoip.org/xml/" ascii wide
        $string3 = "http://checkip.dyndns.org/" ascii wide
        $string4 = "https://api.telegram.org/bot" ascii wide
        $string5 = "http://51.38.247.67:8081/_send_.php?L" ascii wide
        $string6 = "/sendDocument?chat_id=" ascii wide
        $string7 = "/sendMessage?chat_id=" ascii wide
    condition:
        uint16(0) == 0x5A4D and $string4 and 
        3 of ($string1, $string2, $string3, $string5, $string6, $string7)
}
