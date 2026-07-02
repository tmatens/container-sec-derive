module github.com/tmatens/container-sec-derive/gadgets/advise_devices/go

go 1.25.7

// Out-of-tree build: pin the Inspektor Gadget module providing wasmapi/go.
// Keep in lockstep with internal/ig.PinnedIGVersion.
require github.com/inspektor-gadget/inspektor-gadget v0.53.2
