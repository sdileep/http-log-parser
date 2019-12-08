# HTTP Log Parser

This is an implementation of the task to parse a log file containing HTTP requests and to report on its contents. 

For a given log file we want to know,
- The number of unique IP addresses
- The top 3 most visited URLs
- The top 3 most active IP addresses 

<u>Note</u>: a quick implementation, not meant to be exhaustive or performant).

# Prerequisites
- Golang: Latest version available at https://golang.org/dl/

# How to run task

```bash
go mod tidy
go run main.go
```

# How to run task tests

```bash
go mod tidy
go test */*.go -v
```
