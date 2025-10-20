package relay

import (
	"context"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

type resourcePoint struct {
	Timestamp  time.Time `json:"timestamp"`
	CPUPercent float64   `json:"cpuPercent"`
	RSSBytes   uint64    `json:"rssBytes"`
	Goroutines int       `json:"goroutines"`
}

type resourceSnapshot struct {
	Current resourcePoint   `json:"current"`
	History []resourcePoint `json:"history"`
}

type resourceTracker struct {
	proc     *process.Process
	mu       sync.RWMutex
	samples  []resourcePoint
	current  resourcePoint
	maxItems int
}

func newResourceTracker() *resourceTracker {
	p, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		return nil
	}

	return &resourceTracker{
		proc:     p,
		maxItems: 7 * 24 * 60, // 7 days @ 1 sample per minute
	}
}

func (r *resourceTracker) start(ctx context.Context) {
	if r == nil {
		return
	}
	r.sample(ctx)
	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.sample(ctx)
			}
		}
	}()
}

func (r *resourceTracker) sample(ctx context.Context) {
	if r == nil || r.proc == nil {
		return
	}
	now := time.Now()

	cpu, err := r.proc.PercentWithContext(ctx, 0)
	if err != nil {
		cpu = 0
	}
	mem, err := r.proc.MemoryInfoWithContext(ctx)
	var rss uint64
	if err == nil && mem != nil {
		rss = mem.RSS
	}

	point := resourcePoint{
		Timestamp:  now,
		CPUPercent: cpu,
		RSSBytes:   rss,
		Goroutines: runtime.NumGoroutine(),
	}

	r.mu.Lock()
	r.current = point
	r.samples = append(r.samples, point)
	if len(r.samples) > r.maxItems {
		r.samples = r.samples[len(r.samples)-r.maxItems:]
	}
	r.mu.Unlock()
}

func (r *resourceTracker) snapshot() resourceSnapshot {
	if r == nil {
		return resourceSnapshot{}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	history := make([]resourcePoint, len(r.samples))
	copy(history, r.samples)
	return resourceSnapshot{
		Current: r.current,
		History: history,
	}
}
