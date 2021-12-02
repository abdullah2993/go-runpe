package main

import (
	"flag"

	runpe "github.com/abdullah2993/go-runpe"
)

func main() {
	var src, dest string
    var console bool
	flag.StringVar(&src, "src", "C:\\Windows\\System32\\calc.exe", "Source executable")
	flag.StringVar(&dest, "dest", "C:\\Windows\\System32\\notepad.exe", "Destination executable")
	flag.BoolVar(&console, "console", false, "Create the process with the flag CREATE_NEW_CONSOLE (useful for process like cmd.exe)")
	flag.Parse()
	runpe.Inject(src, dest, console)
}
