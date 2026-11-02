# Ubuntu: system DNS for desktop applications

Ubuntu does not need another DNS credential. Use the same user's DoT hostname and server/bootstrap IPv4 shown in the administrator's connection card. A browser's custom DoH setting affects that browser; it does not configure Codex or other desktop applications. The standard Ubuntu network DNS address field does not accept a DoH URL.

If Codex and other applications already work through the system DNS, keep that working configuration. The following is an explicit systemd-resolved setup for installations using NetworkManager, not an automatic installer or a universal VPN configuration.

## Save and inspect

Run `systemctl is-active systemd-resolved`, `resolvectl status` and `readlink -f /etc/resolv.conf`. The standard stub path is `/run/systemd/resolve/stub-resolv.conf`. If another resolver owns the system configuration, configure that resolver instead of replacing files blindly.

Find the active Internet connection with `nmcli connection show --active`. Save its current `ipv4.dns`, `ipv4.ignore-auto-dns`, `ipv6.dns`, `ipv6.ignore-auto-dns` and DNS search/routing settings using `nmcli connection show "CONNECTION NAME"`. Back up any existing resolved drop-ins. These saved values are needed for rollback, especially if manual DNS was already in use.

## Configure the existing credential

Create `/etc/systemd/resolved.conf.d/50-smartdns.conf`, owned by root and mode 0600. Substitute your real bootstrap IPv4 and full personal DoT hostname:

```ini
[Resolve]
DNS=203.0.113.10#personal.dns.example.com
FallbackDNS=
Domains=~.
DNSOverTLS=yes
DNSSEC=no
```

The `#hostname` part supplies SNI and certificate verification; the IP by itself does not identify your DNS profile. Strict TLS avoids falling back to plaintext DNS. Local DNSSEC validation is disabled because this service deliberately rewrites selected answers; TLS still authenticates the chosen resolver. This file contains a DNS credential: keep it out of Git, screenshots and public issue reports.

NetworkManager's per-link DNS can otherwise compete with the global resolver. On the selected ordinary Internet connection, clear the old DNS addresses and stop importing DHCP DNS, retaining its other settings:

```sh
sudo nmcli connection modify "CONNECTION NAME" ipv4.ignore-auto-dns yes ipv4.dns "" ipv6.ignore-auto-dns yes ipv6.dns ""
sudo systemctl restart systemd-resolved
sudo nmcli connection up "CONNECTION NAME"
```

Reactivating the connection briefly reconnects the network. Do not apply these commands to a VPN profile or every connection indiscriminately. Keep any required corporate/private DNS routing explicitly configured; a public resolver cannot resolve private network zones.

Verify `resolvectl status`: the selected SmartDNS server, strict DNS-over-TLS and the intended routing domain must be active, with no competing public resolver. `resolvectl query chatgpt.com` should resolve through that setup. Browser-specific secure DNS must use the matching profile or defer to the OS. A real Codex request is the application check; a successful browser page alone does not confirm system DNS.

## Restore

Remove only the drop-in created for this setup (or restore its saved predecessor). Restore the exact saved NetworkManager DNS and auto-DNS values for that connection. Restart systemd-resolved and reactivate the connection. Do not assume the previous configuration used automatic DNS.

With a real VPN, its DNS and application HTTPS egress must agree; some VPNs override per-link DNS. See [VPN behavior](OPERATIONS.md). Source: [systemd-resolved configuration](https://www.freedesktop.org/software/systemd/man/256/resolved.conf.html).
