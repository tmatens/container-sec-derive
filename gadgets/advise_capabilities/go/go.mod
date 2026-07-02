module github.com/tmatens/container-sec-derive/gadgets/advise_capabilities/go

go 1.25.7

// Out-of-tree build (this repo): pin the Inspektor Gadget module that provides
// wasmapi/go. Keep in lockstep with internal/ig.PinnedIGVersion.
require github.com/inspektor-gadget/inspektor-gadget v0.51.0

// If/when this gadget is upstreamed into the inspektor-gadget tree (Door 1),
// the other gadgets use `module main` with an in-tree replace directive:
//   module main
//   require github.com/inspektor-gadget/inspektor-gadget v0.0.0
//   replace github.com/inspektor-gadget/inspektor-gadget => ../../../
// (and the advice subpackage import path becomes main/advice).
