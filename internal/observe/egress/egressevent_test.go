package egress

import (
	"encoding/json"
	"testing"
)

func TestTcpEventUnmarshalNested(t *testing.T) {
	// The v0.51.0 gadget_process serialization: comm/pid nested under proc,
	// runtime enrichment top-level, dst as an l4endpoint object.
	const line = `{"timestamp_raw":1722451329094958020,"type":"connect","type_raw":0,"src":{"addr":"172.17.0.3","port":51080,"proto":6,"version":4},"dst":{"addr":"1.1.1.1","port":443,"proto":6,"version":4},"proc":{"comm":"curl","pid":4242},"runtime":{"runtimeName":"docker","containerId":"abc123","containerName":"web","containerImageName":"web:1"}}`
	var e tcpEvent
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatal(err)
	}
	if e.Type != "connect" || !e.IsConnect() {
		t.Errorf("type = %q, IsConnect = %v", e.Type, e.IsConnect())
	}
	if e.Dst.Addr != "1.1.1.1" || e.Dst.Port != 443 || e.Dst.Version != 4 {
		t.Errorf("dst = %+v, want 1.1.1.1:443 v4", e.Dst)
	}
	if e.Src.Addr != "172.17.0.3" || e.Src.Port != 51080 {
		t.Errorf("src = %+v, want 172.17.0.3:51080", e.Src)
	}
	if e.Proc.Comm != "curl" || e.Proc.Pid != 4242 {
		t.Errorf("proc = %+v, want curl/4242", e.Proc)
	}
	if e.Runtime.ContainerID != "abc123" || e.Runtime.ContainerName != "web" || e.Runtime.ContainerImage != "web:1" {
		t.Errorf("runtime = %+v", e.Runtime)
	}
}

func TestTcpEventUnmarshalFlatFallback(t *testing.T) {
	// Older ig serialization (shown in some docs): flat comm/pid, no proc
	// envelope. The lenient parser fills proc from the flat fields.
	const line = `{"type":"connect","comm":"wget","pid":99,"dst":{"addr":"1.1.1.1","port":80,"version":4},"runtime":{"containerName":"x"}}`
	var e tcpEvent
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatal(err)
	}
	if e.Proc.Comm != "wget" || e.Proc.Pid != 99 {
		t.Errorf("flat fallback proc = %+v, want wget/99", e.Proc)
	}
	// The nested form must win when both are present.
	const both = `{"type":"connect","comm":"flat","pid":1,"proc":{"comm":"nested","pid":2},"dst":{"addr":"1.1.1.1","port":80}}`
	var e2 tcpEvent
	if err := json.Unmarshal([]byte(both), &e2); err != nil {
		t.Fatal(err)
	}
	if e2.Proc.Comm != "nested" || e2.Proc.Pid != 2 {
		t.Errorf("nested should win, got %+v", e2.Proc)
	}
}

func TestTcpEventIsConnect(t *testing.T) {
	for _, c := range []struct {
		typ  string
		want bool
	}{{"connect", true}, {"accept", false}, {"close", false}, {"", false}} {
		if got := (tcpEvent{Type: c.typ}).IsConnect(); got != c.want {
			t.Errorf("IsConnect(%q) = %v, want %v", c.typ, got, c.want)
		}
	}
}
