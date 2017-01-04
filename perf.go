package perf

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/pwaller/perf/gen"
)

// Option configures perf.
type Option func(*Config) error

// Options composes multiple options together.
func Options(options ...Option) Option {
	return func(cfg *Config) error {
		for _, o := range options {
			err := o(cfg)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

// Config describes the setup of the counter.
type Config struct {
	Name string // convenience

	// Arguments to perf_event_open
	CPU     int64  // defaults to -1
	GroupFD int64  // defaults to -1
	Flags   uint64 // defaults to FlagCloexec

	// if set, don't just profile this thread, profile whole process.
	WholeProcess bool

	gen.Attr
}

// Counter represents a single perf counter.
// Use NewCounter to construct.
type Counter struct {
	Name string

	fd      *os.File
	fdPtr   uintptr
	enabled bool
}

// CounterGroup represents a set of counters which may be read together.
// All counters are paused simultaneously during a reading so that
// comparisons between numbers measured in the same group
// (for example, ratios) are meaningful.
// Beware that the number of counters allowed in a group is implementation
// defined. (In other words: it might depend on what CPU you have, read the
// relevant CPU developer manual to find out.)
type CounterGroup struct {
	leader *Counter
	cs     []*Counter

	enabled bool
}

// Read all the counters.
// The group leader is disabled first so that the counts are not disturbed.
func (cs *CounterGroup) Read() ([]uint64, []float64, error) {
	cs.leader.Disable()
	defer cs.leader.Enable()

	var (
		values      []uint64
		percentages []float64
	)
	for _, c := range cs.cs {
		v, p, err := c.Read()
		if err != nil {
			return nil, nil, err
		}
		_ = p // todo
		values = append(values, v)
		percentages = append(percentages, p)
	}
	return values, percentages, nil
}

// Reset sets all counters to zero.
func (cs *CounterGroup) Reset() error {
	cs.leader.Disable()
	defer cs.leader.Enable()

	// Doing a reset on the leader with IocFlagGroup should be equivalent to the
	// loop below but for some reason it is not as good.
	// cs.leader.Reset()

	for _, c := range cs.cs {
		c.Reset()
	}
	return nil
}

// NewCounterGroup constructs a new Counter group.
func NewCounterGroup(opts ...Option) (*CounterGroup, error) {
	leader, err := NewCounter(opts[0])
	if err != nil {
		return nil, err
	}

	cs := &CounterGroup{
		leader: leader,
		cs:     []*Counter{leader},
	}
	for _, o := range opts[1:] {
		if o == nil {
			continue
		}
		c, err := NewCounter(o, Leader(leader))
		if err != nil {
			return nil, err
		}
		cs.cs = append(cs.cs, c)
	}
	return cs, nil
}

// Disable the whole counter group simultaneously.
func (cs *CounterGroup) Disable() error {
	return cs.leader.Disable()
}

// Enable the whole counter group simultaneously.
func (cs *CounterGroup) Enable() error {
	return cs.leader.Enable()
}

// Close releases file descriptors and other resources associated with the Counters.
func (cs *CounterGroup) Close() error {
	var err error
	err = cs.leader.Close()
	for _, c := range cs.cs {
		err1 := c.Close()
		if err == nil {
			err = err1
		}
	}
	return err
}

func makeConfig(typ uint32, config uint64, name string) Option {
	return func(c *Config) error {
		if c.Config != 0 {
			return fmt.Errorf("counter already configured")
		}
		c.Name = name
		c.Type = typ
		c.Config = config // Confusing names. c.Config is on the Attr.
		return nil
	}
}

// Some things which are countable.
var (
	TaskClock       = makeConfig(gen.TypeSoftware, gen.CountSWTaskClock, "TaskClock")
	PageFaults      = makeConfig(gen.TypeSoftware, gen.CountSWPageFaults, "PageFaults")
	ContextSwitches = makeConfig(gen.TypeSoftware, gen.CountSWContextSwitches, "ContextSwitches")
	CPUMigrations   = makeConfig(gen.TypeSoftware, gen.CountSWCPUMigrations, "CPUMigrations")
	PageFaultsMin   = makeConfig(gen.TypeSoftware, gen.CountSWPageFaultsMin, "PageFaultsMin")
	PageFaultsMaj   = makeConfig(gen.TypeSoftware, gen.CountSWPageFaultsMaj, "PageFaultsMaj")
	AlignmentFaults = makeConfig(gen.TypeSoftware, gen.CountSWAlignmentFaults, "AlignmentFaults")
	EmulationFaults = makeConfig(gen.TypeSoftware, gen.CountSWEmulationFaults, "EmulationFaults")
	Dummy           = makeConfig(gen.TypeSoftware, gen.CountSWDummy, "Dummy")
	BPFOutput       = makeConfig(gen.TypeSoftware, gen.CountSWBpfOutput, "BPFOutput")

	CPUCycles             = makeConfig(gen.TypeHardware, gen.CountHWCPUCycles, "CPUCycles")
	Instructions          = makeConfig(gen.TypeHardware, gen.CountHWInstructions, "Instructions")
	CacheReferences       = makeConfig(gen.TypeHardware, gen.CountHWCacheReferences, "CacheReferences")
	CacheMisses           = makeConfig(gen.TypeHardware, gen.CountHWCacheMisses, "CacheMisses")
	BranchInstructions    = makeConfig(gen.TypeHardware, gen.CountHWBranchInstructions, "BranchInstructions")
	BranchMisses          = makeConfig(gen.TypeHardware, gen.CountHWBranchMisses, "BranchMisses")
	BusCycles             = makeConfig(gen.TypeHardware, gen.CountHWBusCycles, "BusCycles")
	StalledCyclesFrontend = makeConfig(gen.TypeHardware, gen.CountHWStalledCyclesFrontend, "StalledCyclesFrontend")
	StalledCyclesBackend  = makeConfig(gen.TypeHardware, gen.CountHWStalledCyclesBackend, "StalledCyclesBackend")
	RefCPUCycles          = makeConfig(gen.TypeHardware, gen.CountHWRefCPUCycles, "RefCPUCycles")

	L1DReadAccess      = makeConfig(gen.TypeHWCache, gen.CountHWCacheL1d|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultAccess<<16), "L1DReadAccess")
	L1DReadMiss        = makeConfig(gen.TypeHWCache, gen.CountHWCacheL1d|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultMiss<<16), "L1DReadMiss")
	L1DWriteAccess     = makeConfig(gen.TypeHWCache, gen.CountHWCacheL1d|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultAccess<<16), "L1DWriteAccess")
	L1DWriteMiss       = makeConfig(gen.TypeHWCache, gen.CountHWCacheL1d|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultMiss<<16), "L1DWriteMiss")
	L1DPrefetchAccess  = makeConfig(gen.TypeHWCache, gen.CountHWCacheL1d|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultAccess<<16), "L1DPrefetchAccess")
	L1DPrefetchMiss    = makeConfig(gen.TypeHWCache, gen.CountHWCacheL1d|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultMiss<<16), "L1DPrefetchMiss")
	L1IReadAccess      = makeConfig(gen.TypeHWCache, gen.CountHWCacheL1i|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultAccess<<16), "L1IReadAccess")
	L1IReadMiss        = makeConfig(gen.TypeHWCache, gen.CountHWCacheL1i|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultMiss<<16), "L1IReadMiss")
	L1IWriteAccess     = makeConfig(gen.TypeHWCache, gen.CountHWCacheL1i|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultAccess<<16), "L1IWriteAccess")
	L1IWriteMiss       = makeConfig(gen.TypeHWCache, gen.CountHWCacheL1i|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultMiss<<16), "L1IWriteMiss")
	L1IPrefetchAccess  = makeConfig(gen.TypeHWCache, gen.CountHWCacheL1i|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultAccess<<16), "L1IPrefetchAccess")
	L1IPrefetchMiss    = makeConfig(gen.TypeHWCache, gen.CountHWCacheL1i|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultMiss<<16), "L1IPrefetchMiss")
	LLReadAccess       = makeConfig(gen.TypeHWCache, gen.CountHWCacheLl|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultAccess<<16), "LlReadAccess")
	LLReadMiss         = makeConfig(gen.TypeHWCache, gen.CountHWCacheLl|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultMiss<<16), "LlReadMiss")
	LLWriteAccess      = makeConfig(gen.TypeHWCache, gen.CountHWCacheLl|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultAccess<<16), "LlWriteAccess")
	LLWriteMiss        = makeConfig(gen.TypeHWCache, gen.CountHWCacheLl|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultMiss<<16), "LlWriteMiss")
	LLPrefetchAccess   = makeConfig(gen.TypeHWCache, gen.CountHWCacheLl|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultAccess<<16), "LlPrefetchAccess")
	LLPrefetchMiss     = makeConfig(gen.TypeHWCache, gen.CountHWCacheLl|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultMiss<<16), "LlPrefetchMiss")
	DTLBReadAccess     = makeConfig(gen.TypeHWCache, gen.CountHWCacheDtlb|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultAccess<<16), "DTLBReadAccess")
	DTLBReadMiss       = makeConfig(gen.TypeHWCache, gen.CountHWCacheDtlb|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultMiss<<16), "DTLBReadMiss")
	DTLBWriteAccess    = makeConfig(gen.TypeHWCache, gen.CountHWCacheDtlb|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultAccess<<16), "DTLBWriteAccess")
	DTLBWriteMiss      = makeConfig(gen.TypeHWCache, gen.CountHWCacheDtlb|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultMiss<<16), "DTLBWriteMiss")
	DTLBPrefetchAccess = makeConfig(gen.TypeHWCache, gen.CountHWCacheDtlb|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultAccess<<16), "DTLBPrefetchAccess")
	DTLBPrefetchMiss   = makeConfig(gen.TypeHWCache, gen.CountHWCacheDtlb|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultMiss<<16), "DTLBPrefetchMiss")
	ITLBReadAccess     = makeConfig(gen.TypeHWCache, gen.CountHWCacheItlb|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultAccess<<16), "ITLBReadAccess")
	ITLBReadMiss       = makeConfig(gen.TypeHWCache, gen.CountHWCacheItlb|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultMiss<<16), "ITLBReadMiss")
	ITLBWriteAccess    = makeConfig(gen.TypeHWCache, gen.CountHWCacheItlb|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultAccess<<16), "ITLBWriteAccess")
	ITLBWriteMiss      = makeConfig(gen.TypeHWCache, gen.CountHWCacheItlb|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultMiss<<16), "ITLBWriteMiss")
	ITLBPrefetchAccess = makeConfig(gen.TypeHWCache, gen.CountHWCacheItlb|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultAccess<<16), "ITLBPrefetchAccess")
	ITLBPrefetchMiss   = makeConfig(gen.TypeHWCache, gen.CountHWCacheItlb|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultMiss<<16), "ITLBPrefetchMiss")
	BPUReadAccess      = makeConfig(gen.TypeHWCache, gen.CountHWCacheBpu|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultAccess<<16), "BPUReadAccess")
	BPUReadMiss        = makeConfig(gen.TypeHWCache, gen.CountHWCacheBpu|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultMiss<<16), "BPUReadMiss")
	BPUWriteAccess     = makeConfig(gen.TypeHWCache, gen.CountHWCacheBpu|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultAccess<<16), "BPUWriteAccess")
	BPUWriteMiss       = makeConfig(gen.TypeHWCache, gen.CountHWCacheBpu|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultMiss<<16), "BPUWriteMiss")
	BPUPrefetchAccess  = makeConfig(gen.TypeHWCache, gen.CountHWCacheBpu|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultAccess<<16), "BPUPrefetchAccess")
	BPUPrefetchMiss    = makeConfig(gen.TypeHWCache, gen.CountHWCacheBpu|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultMiss<<16), "BPUPrefetchMiss")
	NodeReadAccess     = makeConfig(gen.TypeHWCache, gen.CountHWCacheNode|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultAccess<<16), "NodeReadAccess")
	NodeReadMiss       = makeConfig(gen.TypeHWCache, gen.CountHWCacheNode|(gen.CountHWCacheOpRead<<8)|(gen.CountHWCacheResultMiss<<16), "NodeReadMiss")
	NodeWriteAccess    = makeConfig(gen.TypeHWCache, gen.CountHWCacheNode|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultAccess<<16), "NodeWriteAccess")
	NodeWriteMiss      = makeConfig(gen.TypeHWCache, gen.CountHWCacheNode|(gen.CountHWCacheOpWrite<<8)|(gen.CountHWCacheResultMiss<<16), "NodeWriteMiss")
	NodePrefetchAccess = makeConfig(gen.TypeHWCache, gen.CountHWCacheNode|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultAccess<<16), "NodePrefetchAccess")
	NodePrefetchMiss   = makeConfig(gen.TypeHWCache, gen.CountHWCacheNode|(gen.CountHWCacheOpPrefetch<<8)|(gen.CountHWCacheResultMiss<<16), "NodePrefetchMiss")
)

// BuiltinCounters lists all counters.
var BuiltinCounters = []Option{
	TaskClock, PageFaults, ContextSwitches, CPUMigrations, PageFaultsMin,
	PageFaultsMaj, AlignmentFaults, EmulationFaults, Dummy, BPFOutput,

	CPUCycles, Instructions, CacheReferences, CacheMisses,
	BranchInstructions, BranchMisses,
	BusCycles, StalledCyclesFrontend,
	// StalledCyclesBackend,
	RefCPUCycles,
}

// Leader specifies the group leader for a counter.
// If a leader is enabled/disabled
func Leader(c *Counter) Option {
	return func(cfg *Config) error {
		cfg.GroupFD = int64(c.fdPtr)
		return nil
	}
}

// Disabled specifies that the counter should start off disabled.
func Disabled(c *Config) error {
	c.Disabled = 1
	return nil
}

// Pinned specifies that the counter group should be pinned.
func Pinned(c *Config) error {
	c.Pinned = 1
	return nil
}

// NewCounter creates a new Counter which reads only the current thread.
func NewCounter(options ...Option) (*Counter, error) {
	cfg := &Config{
		GroupFD: -1,
		CPU:     -1,
		Flags:   gen.FlagFdCloexec,

		Attr: gen.Attr{
			// We read on behalf of the library user in this format.
			ReadFormat: gen.FormatTotalTimeEnabled | gen.FormatTotalTimeRunning,

			// Defaults. Overrideable.
			ExcludeHV:     1,
			ExcludeKernel: 1,
			ExcludeIdle:   1,
		},
	}
	for _, o := range options {
		if o == nil {
			panic("nil")
		}
		err := o(cfg)
		if err != nil {
			return nil, err
		}
	}

	pid := int64(syscall.Getpid())
	if !cfg.WholeProcess {
		// Just measure this thread.
		runtime.LockOSThread()
		pid = int64(syscall.Gettid())
	}

	// log.Printf("Open %v", cfg.Name)
	fd, err := perfEventOpen(&cfg.Attr, pid, cfg.CPU, cfg.GroupFD, cfg.Flags)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no such counter %q", cfg.Name)
	}
	if err != nil {
		return nil, err
	}

	c := &Counter{
		Name:    cfg.Name,
		fd:      fd,
		fdPtr:   fd.Fd(),
		enabled: cfg.Disabled == 0,
	}

	mu.Lock()
	counters[c] = struct{}{}
	mu.Unlock()

	// Hard learned lesson: first read may be junk, do it here.
	_, _, err = c.Read()
	if err != nil {
		return nil, err
	}

	err = c.Reset() // Start the counter off at zero.
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Read the counter.
// Returns the count and the fraction of the time the counter was counting.
// The counter is paused while it is read and re-enabled after
// if it was enabled before reading.
func (c *Counter) Read() (uint64, float64, error) {
	if c.enabled {
		c.Disable()
		defer c.Enable()
	}

	var v struct{ Count, Enabled, Running uint64 }
	err := binary.Read(c.fd, binary.LittleEndian, &v)
	frac := float64(v.Running) / float64(v.Enabled)
	return uint64(v.Count), frac, err
}

func (c *Counter) ioctl(ioctl uintptr) error {
	_, _, err := syscall.RawSyscall(syscall.SYS_IOCTL, c.fdPtr, ioctl, 0)
	if err != 0 {
		return os.NewSyscallError("ioctl", err)
	}
	return nil
}

// Reset the counter to zero.
func (c *Counter) Reset() error { return c.ioctl(gen.EventIocReset) }

// Disable the counter.
func (c *Counter) Disable() error {
	err := c.ioctl(gen.EventIocDisable)
	c.enabled = false
	return err
}

// Enable the counter.
func (c *Counter) Enable() error {
	c.enabled = true
	return c.ioctl(gen.EventIocEnable)
}

func perfEventOpen(
	a *gen.Attr, pid, cpu, groupFD int64, flags uint64,
) (*os.File, error) {
	a.Size = gen.AttrSizeVer5

	ptr, alloc := a.PassRef()
	defer alloc.Free()

	fd, _, err := syscall.Syscall6(
		syscall.SYS_PERF_EVENT_OPEN,
		uintptr(unsafe.Pointer(ptr)),
		uintptr(pid),
		uintptr(cpu),
		uintptr(groupFD),
		uintptr(flags),
		0,
	)
	if err != 0 {
		return nil, os.NewSyscallError("perf counter open", err)
	}

	name := fmt.Sprintf("<perf counter fd=%d>", fd)
	return os.NewFile(fd, name), nil
}

// Close frees the file descriptor and other resources associated with the counter.
func (c *Counter) Close() error {
	mu.Lock()
	defer mu.Unlock()
	delete(counters, c)

	return c.fd.Close()
}

// Each counter keeps track of whether it is enabled so that Read can correctly
// pause the counter while taking a reading.
var (
	mu       sync.Mutex
	counters = map[*Counter]struct{}{}
)

func setAllCountersEnabled(enabled bool) {
	mu.Lock()
	for c := range counters {
		c.enabled = enabled
	}
	mu.Unlock()
}

// Disable all counters across the whole process.
func Disable() {
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_TASK_PERF_EVENTS_DISABLE, 0, 0)
	setAllCountersEnabled(false) // after disabling
}

// Enable all counters across the whole process.
func Enable() {
	setAllCountersEnabled(true) // before enabling
	syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_TASK_PERF_EVENTS_ENABLE, 0, 0)
}

// ReadCounterDefs parses definitions from ...
func ReadCounterDefs(r io.Reader) ([]Option, error) {
	cr := csv.NewReader(r)
	cr.Comma = '\t'
	data, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	var options []Option
	for _, record := range data {
		var eventCode, umask uint64
		fmt.Sscanf(record[0], "0x%x", &eventCode)
		fmt.Sscanf(record[1], "0x%x", &umask)
		cfg := (umask << 8) | eventCode
		c := makeConfig(gen.TypeRaw, cfg, record[2]+"_"+fmt.Sprintf("%04x", cfg))
		options = append(options, c)
	}
	return options, nil
}
