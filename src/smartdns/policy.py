"""Exact OS connectivity probes: always direct and unfiltered, independent of catalog imports."""

CONNECTIVITY_NAMES = frozenset(
    {
        "connectivitycheck.gstatic.com",
        "connectivitycheck.android.com",
        "www.google.com",
        "connectivitycheck.platform.hicloud.com",
        "connectivitycheck.samsung.com",
        "connectivitycheck.gstatic.cn",
        "www.gstatic.com",
        "www.msftconnecttest.com",
        "ipv6.msftconnecttest.com",
        "dns.msftncsi.com",
        "www.msftncsi.com",
        "captive.apple.com",
        "www.apple.com",
        "captive.apple.com.edgekey.net",
    }
)
SYSTEM_SERVICE = "system-adult"

# These clients use native game transports, not the HTTPS listener. Keep resources proxied.
DIRECT_GAME_NAMES = frozenset(
    {
        "game.clashroyaleapp.com",
        "game.brawlstarsgame.com",
        "gamea.clashofclans.com",
        "game.clashofclans.com",
        "game.haydaygame.com",
        "game.boombeachgame.com",
        "game.squadbustersgame.com",
        "game.mocogame.com",
    }
)
