package perf

import (
	"log"
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
