// Testable examples.

package cap_test

import (
	"fmt"
	"log"

	cap_ "kernel.org/pub/linux/libs/security/libcap/cap"
)

func ExampleSet_Fill() {
	// This example does not need to use a package alias `cap_`.
	// It is declared this way to make examples on the go.dev doc
	// site render and run. This workaround is needed until the
	// site is fixed as per:
	// https://github.com/golang/go/issues/70611
	c, err := cap_.FromText("cap_setfcap=p")
	if err != nil {
		log.Fatalf("failed to parse: %v", err)
	}
	c.Fill(cap_.Effective, cap_.Permitted)
	c.ClearFlag(cap_.Permitted)
	c.Fill(cap_.Inheritable, cap_.Effective)
	c.ClearFlag(cap_.Effective)
	fmt.Println(c)
	// Output: cap_setfcap=i
}

func ExampleSet_Export() {
	// This example does not need to use a package alias `cap_`.
	// It is declared this way to make examples on the go.dev doc
	// site render and run. This workaround is needed until the
	// site is fixed as per:
	// https://github.com/golang/go/issues/70611
	c, err := cap_.FromText("cap_setuid=ep")
	if err != nil {
		log.Fatalf("failed to parse: %v", err)
	}
	b1, err := c.Export()
	if err != nil {
		log.Fatalf("export failed: %v", err)
	}
	fmt.Printf("default %q export: %02x\n", c, b1)
	cap_.MinExtFlagSize = 0
	b2, err := c.Export()
	if err != nil {
		log.Fatalf("export failed: %v", err)
	}
	fmt.Printf("minimal %q export: %02x\n", c, b2)
	// Output:
	// default "cap_setuid=ep" export: 90c2015108808000000000000000000000000000000000000000000000
	// minimal "cap_setuid=ep" export: 90c2015101808000
}

func ExampleImport() {
	// This example does not need to use a package alias `cap_`.
	// It is declared this way to make examples on the go.dev doc
	// site render and run. This workaround is needed until the
	// site is fixed as per:
	// https://github.com/golang/go/issues/70611
	d := []byte{0x90, 0xc2, 0x01, 0x51, 0x01, 0x80, 0x80, 0x00}
	c, err := cap_.Import(d)
	if err != nil {
		log.Fatalf("failed to parse: %v", err)
	}
	fmt.Printf("import of %02x is %q\n", d, c)
	// Output: import of 90c2015101808000 is "cap_setuid=ep"
}
