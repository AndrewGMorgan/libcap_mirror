// Testable examples.

package cap_test

import (
	"fmt"
	"log"

	bug70630 "kernel.org/pub/linux/libs/security/libcap/cap"
)

func ExampleSet_Fill() {
	// `bug70630` should just be `cap` (i.e there is no need for
	// "real" code to alias the package), but that bug explains
	// that the go.dev website is unable to support this.
	c, err := bug70630.FromText("cap_setfcap=p")
	if err != nil {
		log.Fatalf("failed to parse: %v", err)
	}
	c.Fill(bug70630.Effective, bug70630.Permitted)
	c.ClearFlag(bug70630.Permitted)
	c.Fill(bug70630.Inheritable, bug70630.Effective)
	c.ClearFlag(bug70630.Effective)
	fmt.Println(c)
	// Output: cap_setfcap=i
}
