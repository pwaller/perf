package perf

import (
	"log"
	"os"
	"testing"
	"time"
)

func TestFoo(t *testing.T) {
	t.Logf("Hello.")

	c, err := NewCounter(Instructions)
	if err != nil {
		t.Fatal(err)
	}
	v, _, err := c.Read()
	t.Logf("v=%d, err=%v", v, err)
	for i := 0; i < 1000000; i++ {
	}
	err = c.Reset()
	if err != nil {
		t.Fatal(err)
	}
	v, _, err = c.Read()
	// Enable()
	// c.Enable()
	t.Logf("v=%d, err=%v", v, err)
	for j := 0; j < 20; j++ {
		c.Reset()
		for i := 0; i < 1000000; i++ {
		}
		v, _, err = c.Read()
		t.Logf("v=%d, err=%v", v, err)
	}
	c.Reset()
	v1, _, _ := c.Read()
	c.Reset()
	v2, _, _ := c.Read()
	c.Reset()
	v3, _, _ := c.Read()
	c.Reset()
	v4, _, _ := c.Read()
	t.Log(v1, v2, v3, v4)
}

func TestAllCounters(t *testing.T) {
	cs, err := NewCounters(BuiltinCounters...)
	if err != nil {
		t.Fatal(err)
	}

	cs.Reset()

	for i := 0; i < 1000000; i++ {
	}

	vs, ps, err := cs.Read()
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range cs.cs {
		log.Println(c.Name, vs[i], ps[i])
	}

	cs.Reset()

	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		// Spin
	}

	vs, ps, err = cs.Read()
	if err != nil {
		t.Fatal(err)
	}

	log.Println("--")
	for i, c := range cs.cs {
		log.Println(c.Name, vs[i], ps[i])
	}
}

func TestFooBar(t *testing.T) {
	fd, err := os.Open("evs.tsv")
	if err != nil {
		t.Fatal(err)
	}
	opts, err := ReadRawCounter(fd)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("len=%d", len(opts))

	opts = append([]Option{Options(TaskClock, Pinned), ContextSwitches}, opts...)

	counters := []*Counters{}
	for i := 0; i < len(opts); i += 2 {
		cs, err := NewCounters(opts[i : i+2]...)
		if err != nil {
			continue
			log.Fatal(err)
		}
		counters = append(counters, cs)
	}

	// cs, err := NewCounters(opts[12:17]...)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	Disable()
	for _, cs := range counters {
		cs.Reset()
	}
	Enable()

	for i := 0; i < 10000000000; i++ {
	}

	Disable()

	// deadline := time.Now().Add(100 * time.Millisecond)
	// for time.Now().Before(deadline) {
	// 	// Spin
	// }

	for j, cs := range counters {
		vs, ps, err := cs.Read()
		if err != nil {
			t.Fatal(err)
		}

		for i, c := range cs.cs {
			log.Printf("%4d %-70v %11d %5.02f", j, c.Name, int64(float64(vs[i])/ps[i]), ps[i]*100)
		}
	}
}
