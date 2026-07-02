module main

go 1.25.7

// Out-of-tree build (this repo): pin the Inspektor Gadget module that provides
// wasmapi/go. Keep in lockstep with internal/ig.PinnedIGVersion.
require github.com/inspektor-gadget/inspektor-gadget v0.51.0

// If/when this gadget is upstreamed into the inspektor-gadget tree (Door 1),
// replace the require above with the in-tree replace directive the other
// gadgets use:
//   require github.com/inspektor-gadget/inspektor-gadget v0.0.0
//   replace github.com/inspektor-gadget/inspektor-gadget => ../../../
