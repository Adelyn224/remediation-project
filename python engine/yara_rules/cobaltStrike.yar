rule cobaltStrike_rule : CobaltStrike exe {
    meta:
        description = "Detects the presence of a Cobalt Strike binary"
        author = "me"
        date = "20/02/2026" 
        version = "1.0" 
    strings:
        $string1 = "f:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\src\\mfc\\auxdata.cpp"
        $string2 = "f:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\include\\afxwin2.inl"
        $string3 = "f:\\dd\\vctools\\vc7libs\\ship\\atlmfc\\src\\mfc\\appcore.cpp"
        $string4 = "GetSystemTimeAsFileTime"
    condition:
        $string1 and $string2 and $string3 and $string4
}
