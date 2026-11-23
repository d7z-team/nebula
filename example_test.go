package nebula_test

import (
	"encoding/json"
	"fmt"

	"code.d7z.net/d7z-team/nebula"
)

func ExampleTopology_Validate() {
	// A host can preflight its approved topology before binding any sockets.
	const config = `{
   "network": "demo",
   "networks": ["10.13.0.0/24", "fd13::/64"],
   "members": [
     {"ipv4":"10.13.0.1","ipv6":"fd13::1","restricted":true,"links":["10.13.0.2@fd13::2"]},
     {"ipv4":"10.13.0.2","ipv6":"fd13::2","links":["10.13.0.1@fd13::1"]}
   ]
 }`
	var topology nebula.Topology
	if err := json.Unmarshal([]byte(config), &topology); err != nil {
		fmt.Println(err)
		return
	}
	if err := topology.Validate(); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("approved neighbor:", topology.Members[0].Links[0])
	// Output: approved neighbor: 10.13.0.2@fd13::2
}
