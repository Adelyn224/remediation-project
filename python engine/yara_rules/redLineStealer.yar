rule redLineStealer_rule : RedLineStealer exe {
    meta:
        description = "Detects the presence of a RedLine Stealer binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $hex_string = {4D 5A} // "MZ" header of the PE file
        $string1 = "baiohttp\\_http_parser.cp314-win_amd64.pyd"
        $string2 = "baiohttp\\_websocket\\reader_c.cp314-win_amd64.pyd"
        $string3 = "HttpSendRequestW"
        $string4 = "HttpOpenRequestW"
    condition:
        $hex_string and $string1 and $string2 and $string3 and $string4 
}
