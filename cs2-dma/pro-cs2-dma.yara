rule Pro_CS2_DMA_Cheat
{
    meta:
        author = "yourname"
        description = "Detects the Pro-CS2 DMA cheat binary"
        date = "2025-05-12"

    strings:
        $url1 = "https://raw.githubusercontent.com/a2x/cs2-dumper/" nocase
        $url2 = "https://github.com/Enoouo/Pro-CS2_DMA" nocase
        $str1 = "Memory encryption detected"
        $str2 = "CryptEncrypt"
        $api1 = "GetAsyncKeyState"

    condition:
        uint16(0) == 0x5A4D and
        all of ($url*) and 2 of ($str* or $api*)
}
