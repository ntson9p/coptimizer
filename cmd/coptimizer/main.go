// Command coptimizer finds what fills the Windows system drive and helps
// reclaim the space safely. See docs/plan.md.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is set at build time: -ldflags "-X main.version=…".
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("coptimizer", version)
		return
	}
	fmt.Fprintln(os.Stderr, "coptimizer", version+": nothing to run yet, this is the phase 0 scaffold (see docs/plan.md)")
	os.Exit(2)
}
