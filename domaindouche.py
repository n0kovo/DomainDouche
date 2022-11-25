"""Domain enumeration script abusing the 'suggestions' feature
when typing out domains on https://securitytrails.com/dns-trails.
Very handy for quickly finding potentially related domains from a name."""

import argparse
import json
import multiprocessing
import signal
import string
import sys
from argparse import RawTextHelpFormatter
from http.cookies import SimpleCookie
from itertools import product

import requests
from rich.console import Console
from rich.progress import Progress

parser = argparse.ArgumentParser(
    formatter_class=RawTextHelpFormatter,
    prog=sys.argv[0],
    description="""Abuses SecurityTrails API to find related domains by keyword.
Go to https://securitytrails.com/dns-trails, solve any CAPTCHA you might encounter,
copy the raw value of your Cookie and User-Agent headers and use them with \
the -c and -a arguments.""",
)

parser.add_argument("keyword", help="keyword to append brute force string to")
parser.add_argument(
    "-n",
    "--num",
    metavar="N",
    type=int,
    default=2,
    required=False,
    help="number of characters to brute force (default: 2)",
)
parser.add_argument(
    "-c",
    "--cookie",
    metavar="COOKIE",
    type=str,
    required=True,
    help="raw cookie string",
)
parser.add_argument(
    "-a",
    "--useragent",
    metavar="USER_AGENT",
    type=str,
    required=True,
    help="user-agent string (must match the browser where the cookies are from)",
)
parser.add_argument(
    "-w",
    "--workers",
    metavar="NUM",
    type=str,
    required=False,
    help="number of workers (default: 5)",
)
parser.add_argument(
    "-o", "--output", metavar="OUTFILE", required=False, help="output file path"
)
args = parser.parse_args()


cookie = SimpleCookie()
cookie.load(args.cookie)
cookies = {k: v.value for k, v in cookie.items()}
headers = {
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": args.useragent,
    "Accept": "text/html,application/xhtml+xml,application/xml;\
q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Sec-Gpc": "1",
    "Accept-Language": "da-DK,da;q=0.6",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Encoding": "gzip, deflate",
}


def get_suggestions(brute_string):
    """Makes the HTTP request and returns a list of suggested domains"""
    url = f"https://securitytrails.com/app/api/autocomplete/domain/{args.keyword}{brute_string}"
    req = requests.get(url, cookies=cookies, headers=headers)
    return json.loads(req.text)["suggestions"]


def call_get_suggestions(params):
    """Call the worker function"""
    return get_suggestions(*params)


def initializer():
    """Ignore SIGINT in child workers."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)


combinations = []
for letter_count in range(1, args.num + 1):
    combinations = combinations + [
        "".join(i) for i in list(product(string.ascii_lowercase, repeat=letter_count))
    ]

progress_console = Console(log_time=False, log_path=False, file=sys.stderr)
results = []


if __name__ == "__main__":
    try:
        try:
            algo_params = []
            results = []

            for x in combinations:
                algo_params.append([x])

            with Progress(
                console=progress_console,
                redirect_stdout=False,
                redirect_stderr=False,
                transient=True,
            ) as progress:

                task_id = progress.add_task("[bold magenta]Brute-forcing...", total=len(algo_params))
                progress.print("""[green]
 _                 _                
| \ _ __  _  o __ | \ _     _ |_  _ 
|_/(_)|||(_| | | ||_/(_)|_|(_ | |(/_
 _________________________________[/green]                                                                  
                        by [bold magenta]n0kovo[/bold magenta]""")
                progress.print("\nStarting enumeration...\n", style="bold magenta")
                with multiprocessing.Pool(processes=5, initializer=initializer) as pool:

                    for result in pool.imap(call_get_suggestions, algo_params):
                        new_found = list(set(result) - set(results))

                        results = results + new_found
                        for domain in new_found:
                            progress.print(domain, style="green")
                            if args.output:
                                with open(args.output, "w+", encoding="utf-8") as outfile:
                                    outfile.write(f"{domain}\n")

                        progress.advance(task_id)

        except (KeyError, json.decoder.JSONDecodeError):
            progress.stop()
            progress_console.print(
                "[bold red]UNRECOGNIZED REPLY! TRY WITH FRESH COOKIE.[/bold red]"
            )
            sys.exit()

    except KeyboardInterrupt:
        progress_console.print(
            "\n[bold magenta]Ctrl-C detected. Exiting...[/bold magenta]\n"
        )

    # If script output is piped, print results to stdout
    # (progress prints to stderr only)
    if not sys.stdout.isatty():
        for result in results:
            for domain in results:
                print(domain)
