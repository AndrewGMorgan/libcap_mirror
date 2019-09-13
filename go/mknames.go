// Program mknames parses the cap_names.h file and creates an equivalent names.go file.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strings"
)

var (
	header = flag.String("header", "", "name of header file")
)

func main() {
	flag.Parse()

	if *header == "" {
		log.Fatal("usage: mknames --header=.../cap_names.h")
	}
	d, err := ioutil.ReadFile(*header)
	if err != nil {
		log.Fatal("reading:", err)
	}

	b := bytes.NewBuffer(d)

	var list []string
	for {
		line, err := b.ReadString('\n')
		if err == io.EOF {
			break
		}
		if !strings.Contains(line, `"`) {
			continue
		}
		i := strings.Index(line, `"`)
		line = line[i+1:]
		i = strings.Index(line, `"`)
		line = line[:i]
		list = append(list, line)
	}

	// generate package file names.go
	fmt.Print(`package cap

/* ** DO NOT EDIT THIS FILE. IT WAS AUTO-GENERATED BY LIBCAP'S GO BUILDER (mknames.go) ** */

// NamedCount holds the number of capabilities with official names.
const NamedCount = `, len(list), `

// CHOWN etc., are the named capability bits on this system. The
// canonical source for each name is the "uapi/linux/capabilities.h"
// file, which is hard-coded into this package.
const (
`)
	bits := make(map[string]string)
	for i, name := range list {
		v := strings.ToUpper(strings.TrimPrefix(name, "cap_"))
		bits[name] = v
		if i == 0 {
			fmt.Println(v, " Value =  iota")
		} else {
			fmt.Println(v)
		}
	}
	fmt.Print(`)

var names = map[Value]string{
`)
	for _, name := range list {
		fmt.Printf("%s: %q,\n", bits[name], name)
	}
	fmt.Print(`}

var bits = map[string]Value {
`)
	for _, name := range list {
		fmt.Printf("%q: %s,\n", name, bits[name])
	}
	fmt.Println(`}`)
}