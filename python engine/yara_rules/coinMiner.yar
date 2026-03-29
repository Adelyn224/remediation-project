rule coinMiner_rule : CoinMiner exe stealer {
    meta:
        description = "Detects the presence of a coin miner binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $hex_string = {4D 5A 78} // "MZx" is an observed byte sequence in the analysed binary
        $string1 = "Panicked during a panic. Aborting."
        $string2 = "Unable to dump stack trace: debug info stripped"
    condition:
        $hex_string and $string1 and $string2
}
