# Windows specific info

## DNS name resolution

To prevent DNS leaks lightway client uses [NRTP](https://www.island.io/blog/man-7-windows-nrpt) (Name Resolution Policy Table)
rule to try and route all DNS queries via tunnel.

Unfortunately some programs (ex. nslookup) do not obey this which might still lead to DNS leaks.

Another issue is that when lightway client crashes the NRPT rule might be left leading to name resolution problems.
The old rule will be deleted on next client connection.
In order to remove the rule manually following PowerShell (run as Administrator) command might be used:
`Get-DnsClientNrptRule | Where-Object -Property Comment -eq 'lightway-dns' | Remove-DnsClientNrptRule -Force`