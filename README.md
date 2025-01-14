# urlscan

URLScan is a tool for scanning and analyzing URLs to detect potential security threats. It helps in identifying malicious URLs, phishing sites, and other online threats.

## Installation

To install URLScan, clone the repository and install the dependencies:

```bash
go get -u github.com/tin3ga/urlscan
```

## Usage

To scan a URL

```go
package main
  import(
    "fmt"

    "github.com/tin3ga/urlscan"
  )

  func main() {
    results, err := urlscan.Scan("4gg5f4123eg4gg7a58d502dfc3f2898g", "https://google.com")
	if err != nil {
		fmt.Print(err)
	}
	fmt.Print(results)
    }
  }
```

## License

This project is licensed under the [MIT license][1].

[1]: LICENSE
