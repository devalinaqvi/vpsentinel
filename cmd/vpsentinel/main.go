package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/devalinaqvi/vpsentinel/internal/checks"
	"github.com/devalinaqvi/vpsentinel/internal/checks/ports"
	"github.com/devalinaqvi/vpsentinel/internal/report"
	"github.com/devalinaqvi/vpsentinel/internal/scan"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("vpsentinel", version)
		return
	}

	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output findings as JSON")
	procRoot := fs.String("proc", "/proc", "proc filesystem root (for testing)")

	// Skip the "scan" subcommand word if present, then parse flags.
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "scan" {
		args = args[1:]
	}
	_ = fs.Parse(args)

	checkList := []checks.Check{
		&ports.Check{ProcRoot: *procRoot},
	}
	result := scan.Run(context.Background(), version, checkList)

	var err error
	if *asJSON {
		err = report.JSON(os.Stdout, result)
	} else {
		err = report.Text(os.Stdout, result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
