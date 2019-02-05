package main

import (
	"flag"

	runpe "github.com/abdullah2993/go-runpe"
)

func main() {
	var src, dest string
	flag.StringVar(&src, "src", "C:\\Windows\\System32\\calc.exe", "Source executable")
	flag.StringVar(&dest, "dest", "C:\\Windows\\System32\\notepad.exe", "Destenation executable")
	flag.Parse()
	runpe.Inject(src, dest)
}
