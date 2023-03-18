AWSScrape is a tool designed to scrape SSL certificates from all AWS IP ranges, searching for specific keywords in the certificates' Common Name (CN), Organization (O), and Organizational Unit (OU) fields.

## Installation

1. Clone this repository:

```
git clone https://github.com/jhaddix/awsscrape.git
cd awsscrape
```

## Usage

Run the script as follows:

```
go run awsGO.go -keyword=<KEYWORD>  
```

Replace "example" with the keyword you want to search for in the SSL certificates.

The script will download SSL certificates from the AWS IP ranges and display the IP addresses with matching certificates.
