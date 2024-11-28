// Testable examples.

package cap_test

import (
	"fmt"
	"log"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func ExampleSet_Fill() {
	c, err := cap.FromText("cap_setfcap=p")
	if err != nil {
		log.Fatalf("failed to parse: %v", err)
	}
	c.Fill(cap.Effective, cap.Permitted)
	c.ClearFlag(cap.Permitted)
	c.Fill(cap.Inheritable, cap.Effective)
	c.ClearFlag(cap.Effective)
	fmt.Println(c)
	// Output: cap_setfcap=i
}
