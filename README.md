# Gozuul

Go library and cli that provides methods to scan Netflix Zuul instances in relation to the Netflix [nflx-2016-003](https://github.com/Netflix/security-bulletins/blob/master/advisories/nflx-2016-003.md) Security Advisory.

It has two methods: `PassiveScan` and `ActiveScan`. The first one is safe because it only tries to `POST` to a specific URL without uploading a file, but the second method makes modifications in the target server (if it is vulnerable), because it uploads a payload that when executed by the server makes a callback to the specified callback URL.

To install it just execute:

```bash
go get -v github.com/adevinta/gozuul.git
```

### Examples

#### Passive Scan

```go
package main

func main() {
	rs, err := gozuul.PassiveScan("http://test.example.com")
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n")
}
```

#### Active Scan

```go
package main

func main() {
	c := make(chan bool)
	
	// If a callback is received in the endpoint you control, you should write `true` to the channel. 
	rs, err := gozuul.ActiveScan("http://test.example.com", "http://endpoint-you-control-for-callback.example.com", c)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n")
}
```

#### CLI

```bash
$ gozuul
Provides methods to scan Netflix Zuul instances in relation to the Netflix nflx-2016-003 Security Advisory

Usage:
  gozuul [command]

Available Commands:
  help        Help about any command
  passive     Executes a new passive scan against the specified targets
  passivebulk Executes a new passive scan against the specified targets

Flags:
  -h, --help      help for gozuul
  -v, --verbose   prints verbose information during command execution

Use "gozuul [command] --help" for more information about a command.

$ gozuul passive http://www.adevinta.com
```
