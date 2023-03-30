# AWSScrape
AWSScrape is a tool designed to scrape SSL certificates from all AWS IP ranges, searching for specific keywords in the certificates' Common Name (CN), Organization (O), and Organizational Unit (OU) fields.

[![Twitter](https://img.shields.io/badge/twitter-@jhaddix-blue.svg)](https://twitter.com/jhaddix)
## Installation

1. Clone this repository:

```
git clone https://github.com/jhaddix/awsscrape.git
cd awsscrape
```

## Usage

Run the script as follows:

```
go run awsscrape.go -keyword=<KEYWORD>  
```

| Argument   | Description                                                                                                  |
|------------|--------------------------------------------------------------------------------------------------------------|
| -keyword    | Provide a single keyword to search for in SSL certificates |
| -output | Provide an output file to store results within |
| -randomize | When set, randomize the order in which IP addresses are checked |
| -threads | Specify the number of concurrent threads (default 4) |
| -timeout | Specify the number of seconds to timeout an SSL connection (default 1) |
| -v -verbose | Enable verbose mode |
| -w -wordlist | Specify a file of keywords to check for (on newlines) |

The script will parse the SSL certificates from the AWS IP ranges and display any matching your KEYWORD with the IP addresses of the matching certificates.

Please note that iterating through all AWS IP addresses and checking SSL certificates WILL take a long time to complete.

=================================================================================================================================================

Disclaimer: Usage without a customers permission may constitute a violation of AWS AUP:

* https://aws.amazon.com/security/penetration-testing/
* https://aws.amazon.com/aup/

Use Responsibly
