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
