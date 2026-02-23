rule mirai_rule {
    meta:
        description = "Detects the presence of a self-propagating IoT botnet binary"
        author = "me"
        date = "17/02/2026" 
        version = "1.0" 
    strings:
        $hex_string = {7F 45 4C 46} // ELF header of Linux executables
        $string1 = "Chrome/100.0.4896.127"
        $string2 = "Firefox/99.0"
        $string3 = "Safari/605.1.15"
        $string4 = "Edg/100.0.1185.39"
        $string5 = "/bin/busybox wget http://" // Common command used by Mirai to download additional payloads
        $string6 = "/bin/busybox curl http://" // Another common command used by Mirai for downloading payloads
    condition:
        $hex_string or $string1 or $string2 or $string3 or $string4 or $string5 or $string6
}
