// Copyright (c) 2015 Frank Braun <frank@cryptogroup.net>
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

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
