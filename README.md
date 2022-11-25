# DomainDouche
Abusing SecurityTrails domain suggestion API to find potentially related domains by keyword and brute force.

### Example:
<img src='https://user-images.githubusercontent.com/16690056/204003301-33dcebad-0108-4a95-a01c-96e6c966055f.gif' width='50%'>

### Usage:

```shell
usage: domaindouche.py [-h] [-n N] -c COOKIE -a USER_AGENT [-w NUM] [-o OUTFILE] keyword

Abuses SecurityTrails API to find related domains by keyword.
Go to https://securitytrails.com/dns-trails, solve any CAPTCHA you might encounter,
copy the raw value of your Cookie and User-Agent headers and use them with the -c and -a arguments.

positional arguments:
  keyword               keyword to append brute force string to

options:
  -h, --help            show this help message and exit
  -n N, --num N         number of characters to brute force (default: 2)
  -c COOKIE, --cookie COOKIE
                        raw cookie string
  -a USER_AGENT, --useragent USER_AGENT
                        user-agent string (must match the browser where the cookies are from)
  -w NUM, --workers NUM
                        number of workers (default: 5)
  -o OUTFILE, --output OUTFILE
                        output file path

```
