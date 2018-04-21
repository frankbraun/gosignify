package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/frankbraun/gosignify/signify"
)

func main() {
	if err := signify.Main(os.Args...); err != nil {
		if err != flag.ErrHelp {
			fmt.Fprintf(os.Stderr, "%s: %s\n", os.Args[0], err)
		}
		os.Exit(1)
	}
}
