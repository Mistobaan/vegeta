package vegeta

import (
	"encoding/gob"
	"io"
	"sync"
	"time"
)

func init() {
	gob.Register(&Result{})
}

// Result represents the metrics defined out of an http.Response
// generated by each target hit
type Result struct {
	Code      int
	Timestamp time.Time
	Latency   time.Duration
	BytesOut  uint64
	BytesIn   uint64
	Error     string
}

// Collect concurrently reads Results from multiple io.Readers until all of
// them return io.EOF. Each read Result is passed to the returned Results channel
// while errors will be put in the returned error channel.
func Collect(in ...io.Reader) (<-chan *Result, <-chan error) {
	var wg sync.WaitGroup
	resc := make(chan *Result)
	errs := make(chan error)

	for i := range in {
		wg.Add(1)
		go func(src io.Reader) {
			dec := gob.NewDecoder(src)
			for {
				var r Result
				if err := dec.Decode(&r); err != nil {
					if err == io.EOF {
						wg.Done()
						return
					}
					errs <- err
					continue
				}
				resc <- &r
			}
		}(in[i])
	}

	go func() {
		wg.Wait()
		close(resc)
		close(errs)
	}()

	return resc, errs
}

// Results is a slice of pointers to results with sorting behavior attached.
type Results []*Result

func (r Results) Len() int           { return len(r) }
func (r Results) Less(i, j int) bool { return r[i].Timestamp.Before(r[j].Timestamp) }
func (r Results) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
