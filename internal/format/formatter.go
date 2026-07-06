package format

import (
	"io"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// Formatter renders one observer's derived recommendation across the six
// compose-security output formats that share a common per-observer dispatch
// shape (compose, docker-run, k8s, oci, compose-patch, compose-lint-profile).
//
// Every method takes the whole *sidecar.Sidecar even though most observers only
// need a sub-field (fs → s.FSRecommendation, capadd → s.CapaddValidation): the
// uniform signature is what lets cli.Run drive all five observers through a
// single switch instead of five near-identical ones. Each implementation
// extracts what it needs from s. The two formats that don't fit this shape stay
// package functions: WriteJSON is observer-independent (dispatched once), and
// WriteCapaddComment is an internal preamble helper the capadd formatters call.
type Formatter interface {
	Compose(w io.Writer, s *sidecar.Sidecar) error
	DockerRun(w io.Writer, s *sidecar.Sidecar) error
	K8s(w io.Writer, s *sidecar.Sidecar) error
	OCI(w io.Writer, s *sidecar.Sidecar) error
	ComposePatch(w io.Writer, s *sidecar.Sidecar, original []byte, inPath, service string) error
	ComposeLintProfile(w io.Writer, s *sidecar.Sidecar, allowExploratory bool) error
}

// The five observer Formatters. They are stateless pass-throughs to the exported
// Write* functions (which the unit and golden tests still call directly), doing
// the same sub-field deref cli.Run did inline before the abstraction — so output
// stays byte-identical. The deref matches the observer's produce invariant: e.g.
// FSFormatter is only ever selected on the --observe fs path, where
// s.FSRecommendation is populated.
var (
	CapsFormatter       Formatter = capsFormatter{}
	FSFormatter         Formatter = fsFormatter{}
	DeviceFormatter     Formatter = deviceFormatter{}
	PrivilegedFormatter Formatter = privilegedFormatter{}
	CapaddFormatter     Formatter = capaddFormatter{}
)

type capsFormatter struct{}

func (capsFormatter) Compose(w io.Writer, s *sidecar.Sidecar) error   { return WriteCompose(w, s) }
func (capsFormatter) DockerRun(w io.Writer, s *sidecar.Sidecar) error { return WriteDockerRun(w, s) }
func (capsFormatter) K8s(w io.Writer, s *sidecar.Sidecar) error       { return WriteK8s(w, s) }
func (capsFormatter) OCI(w io.Writer, s *sidecar.Sidecar) error       { return WriteOCI(w, s) }
func (capsFormatter) ComposePatch(w io.Writer, s *sidecar.Sidecar, original []byte, inPath, service string) error {
	return WriteComposePatch(w, s, original, inPath, service)
}
func (capsFormatter) ComposeLintProfile(w io.Writer, s *sidecar.Sidecar, allowExploratory bool) error {
	return WriteComposeLintProfile(w, s, allowExploratory)
}

type fsFormatter struct{}

func (fsFormatter) Compose(w io.Writer, s *sidecar.Sidecar) error {
	return WriteFSCompose(w, *s.FSRecommendation)
}
func (fsFormatter) DockerRun(w io.Writer, s *sidecar.Sidecar) error {
	return WriteFSDockerRun(w, *s.FSRecommendation)
}
func (fsFormatter) K8s(w io.Writer, s *sidecar.Sidecar) error {
	return WriteFSK8s(w, *s.FSRecommendation)
}
func (fsFormatter) OCI(w io.Writer, s *sidecar.Sidecar) error {
	return WriteFSOCI(w, *s.FSRecommendation)
}
func (fsFormatter) ComposePatch(w io.Writer, s *sidecar.Sidecar, original []byte, inPath, service string) error {
	return WriteFSComposePatch(w, *s.FSRecommendation, original, inPath, service)
}
func (fsFormatter) ComposeLintProfile(w io.Writer, s *sidecar.Sidecar, allowExploratory bool) error {
	return WriteFSComposeLintProfile(w, s, allowExploratory)
}

type deviceFormatter struct{}

func (deviceFormatter) Compose(w io.Writer, s *sidecar.Sidecar) error {
	return WriteDeviceCompose(w, *s.DeviceRecommendation)
}
func (deviceFormatter) DockerRun(w io.Writer, s *sidecar.Sidecar) error {
	return WriteDeviceDockerRun(w, *s.DeviceRecommendation)
}
func (deviceFormatter) K8s(w io.Writer, s *sidecar.Sidecar) error {
	return WriteDeviceK8s(w, *s.DeviceRecommendation)
}
func (deviceFormatter) OCI(w io.Writer, s *sidecar.Sidecar) error {
	return WriteDeviceOCI(w, *s.DeviceRecommendation)
}
func (deviceFormatter) ComposePatch(w io.Writer, s *sidecar.Sidecar, original []byte, inPath, service string) error {
	return WriteDeviceComposePatch(w, *s.DeviceRecommendation, original, inPath, service)
}
func (deviceFormatter) ComposeLintProfile(w io.Writer, s *sidecar.Sidecar, allowExploratory bool) error {
	return WriteDeviceComposeLintProfile(w, s, allowExploratory)
}

type privilegedFormatter struct{}

func (privilegedFormatter) Compose(w io.Writer, s *sidecar.Sidecar) error {
	return WritePrivilegedCompose(w, s)
}
func (privilegedFormatter) DockerRun(w io.Writer, s *sidecar.Sidecar) error {
	return WritePrivilegedDockerRun(w, s)
}
func (privilegedFormatter) K8s(w io.Writer, s *sidecar.Sidecar) error {
	return WritePrivilegedK8s(w, s)
}
func (privilegedFormatter) OCI(w io.Writer, s *sidecar.Sidecar) error {
	return WritePrivilegedOCI(w, s)
}
func (privilegedFormatter) ComposePatch(w io.Writer, s *sidecar.Sidecar, original []byte, inPath, service string) error {
	return WritePrivilegedComposePatch(w, s, original, inPath, service)
}
func (privilegedFormatter) ComposeLintProfile(w io.Writer, s *sidecar.Sidecar, allowExploratory bool) error {
	return WritePrivilegedComposeLintProfile(w, s, allowExploratory)
}

type capaddFormatter struct{}

func (capaddFormatter) Compose(w io.Writer, s *sidecar.Sidecar) error {
	return WriteCapaddCompose(w, s.CapaddValidation)
}
func (capaddFormatter) DockerRun(w io.Writer, s *sidecar.Sidecar) error {
	return WriteCapaddDockerRun(w, s.CapaddValidation)
}
func (capaddFormatter) K8s(w io.Writer, s *sidecar.Sidecar) error {
	return WriteCapaddK8s(w, s.CapaddValidation)
}
func (capaddFormatter) OCI(w io.Writer, s *sidecar.Sidecar) error {
	return WriteCapaddOCI(w, s.CapaddValidation)
}
func (capaddFormatter) ComposePatch(w io.Writer, s *sidecar.Sidecar, original []byte, inPath, service string) error {
	return WriteCapaddComposePatch(w, s.CapaddValidation, original, inPath, service)
}
func (capaddFormatter) ComposeLintProfile(w io.Writer, s *sidecar.Sidecar, allowExploratory bool) error {
	return WriteCapaddComposeLintProfile(w, s, allowExploratory)
}
