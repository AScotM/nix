package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Interval time.Duration
	Watch    bool
	Limit    int
	Threads  bool
	Filter   string
	Sort     string
	JSON     bool
	Wide     bool
}
type Metric struct {
	Value     uint64 `json:"value"`
	Available bool   `json:"available"`
}
type Sample struct {
	PID         int    `json:"pid"`
	TGID        int    `json:"tgid"`
	Start       uint64 `json:"start_ticks"`
	Name        string `json:"name"`
	State       string `json:"state"`
	Threads     uint64 `json:"threads"`
	RSS         uint64 `json:"rss_bytes"`
	Priority    int64  `json:"priority"`
	Nice        int64  `json:"nice"`
	Policy      uint64 `json:"policy"`
	Processor   int64  `json:"last_cpu"`
	Allowed     string `json:"allowed_cpus"`
	WChan       string `json:"wchan"`
	Runtime     Metric `json:"runtime_ns"`
	Wait        Metric `json:"wait_ns"`
	Schedules   Metric `json:"schedules"`
	Read        Metric `json:"read_bytes"`
	Write       Metric `json:"write_bytes"`
	Voluntary   Metric `json:"voluntary_context_switches"`
	Involuntary Metric `json:"involuntary_context_switches"`
	Thread      bool   `json:"thread"`
}
type Delta struct {
	Value     uint64 `json:"value"`
	Available bool   `json:"available"`
}
type Record struct {
	Sample      Sample  `json:"process"`
	CPU         Delta   `json:"cpu_ns"`
	Wait        Delta   `json:"wait_ns"`
	Schedules   Delta   `json:"schedules"`
	Read        Delta   `json:"read_bytes"`
	Write       Delta   `json:"write_bytes"`
	Voluntary   Delta   `json:"voluntary_context_switches"`
	Involuntary Delta   `json:"involuntary_context_switches"`
	CPUPercent  float64 `json:"cpu_percent"`
	WaitPercent float64 `json:"wait_percent"`
	ReadBPS     float64 `json:"read_bytes_per_sec"`
	WriteBPS    float64 `json:"write_bytes_per_sec"`
	CtxPS       float64 `json:"context_switches_per_sec"`
	WaitToRun   float64 `json:"wait_to_run_ratio"`
	RatioValid  bool    `json:"ratio_valid"`
}
type Snapshot struct {
	At      time.Time
	Items   map[string]Sample
	Scanned int
	Skipped int
}
type Report struct {
	Time            time.Time `json:"time"`
	IntervalSeconds float64   `json:"interval_seconds"`
	Scanned         int       `json:"scanned"`
	Skipped         int       `json:"skipped"`
	Matched         int       `json:"matched"`
	Records         []Record  `json:"records"`
}

func main() {
	var cfg Config
	var seconds float64
	flag.Float64Var(&seconds, "interval", 2, "sampling interval in seconds")
	flag.BoolVar(&cfg.Watch, "watch", false, "continuously sample until interrupted")
	flag.IntVar(&cfg.Limit, "limit", 20, "maximum entries in each terminal report")
	flag.BoolVar(&cfg.Threads, "threads", false, "include individual tasks from /proc/PID/task")
	flag.StringVar(&cfg.Filter, "filter", "", "case-insensitive process-name filter")
	flag.StringVar(&cfg.Sort, "sort", "cpu", "sort by cpu, wait, io, ctx, sched, rss, pid")
	flag.BoolVar(&cfg.JSON, "json", false, "emit one JSON report per sample")
	flag.BoolVar(&cfg.Wide, "wide", false, "do not truncate process names or wait channels")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "NIX / Linux Scheduler Forensics\nUsage: nix [options]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if seconds < 0.1 || seconds > 3600 || math.IsNaN(seconds) || math.IsInf(seconds, 0) || cfg.Limit < 1 || cfg.Limit > 100000 {
		fatal(errors.New("interval must be 0.1..3600 seconds and limit 1..100000"))
	}
	cfg.Interval = time.Duration(seconds * float64(time.Second))
	valid := map[string]bool{"cpu": true, "wait": true, "io": true, "ctx": true, "sched": true, "rss": true, "pid": true}
	if !valid[cfg.Sort] {
		fatal(fmt.Errorf("unknown sort %q", cfg.Sort))
	}
	if runtime.GOOS != "linux" {
		fatal(errors.New("nix requires Linux"))
	}
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	previous := snapshot(cfg)
	for {
		timer := time.NewTimer(cfg.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		current := snapshot(cfg)
		report := compare(previous, current)
		sortRecords(report.Records, cfg.Sort)
		if cfg.JSON {
			if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
				fatal(err)
			}
		} else {
			if cfg.Watch {
				fmt.Print("\033[2J\033[H")
			}
			render(report, cfg)
		}
		if !cfg.Watch {
			return
		}
		previous = current
	}
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "nix:", err); os.Exit(1) }
func snapshot(cfg Config) Snapshot {
	out := Snapshot{At: time.Now(), Items: make(map[string]Sample)}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		fatal(err)
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		out.Scanned++
		p, err := readSample(pid, pid, false)
		if err != nil {
			out.Skipped++
			continue
		}
		if matches(p, cfg.Filter) {
			out.Items[key(p)] = p
		}
		if !cfg.Threads {
			continue
		}
		tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
		if err != nil {
			continue
		}
		for _, task := range tasks {
			tid, err := strconv.Atoi(task.Name())
			if err != nil || tid <= 0 || tid == pid {
				continue
			}
			t, err := readSample(pid, tid, true)
			if err != nil {
				continue
			}
			if matches(t, cfg.Filter) {
				out.Items[key(t)] = t
			}
		}
	}
	return out
}
func matches(p Sample, filter string) bool {
	return strings.Contains(strings.ToLower(p.Name), strings.ToLower(filter))
}
func key(p Sample) string { return fmt.Sprintf("%d/%d/%d", p.TGID, p.PID, p.Start) }
func readSample(tgid, tid int, thread bool) (Sample, error) {
	base := fmt.Sprintf("/proc/%d", tgid)
	if thread {
		base = fmt.Sprintf("/proc/%d/task/%d", tgid, tid)
	}
	p := Sample{PID: tid, TGID: tgid, Thread: thread}
	data, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return p, err
	}
	line := strings.TrimSpace(string(data))
	l := strings.IndexByte(line, '(')
	r := strings.LastIndexByte(line, ')')
	if l < 0 || r <= l {
		return p, errors.New("malformed stat")
	}
	p.Name = line[l+1 : r]
	f := strings.Fields(line[r+1:])
	if len(f) < 39 {
		return p, errors.New("short stat")
	}
	p.State = f[0]
	p.Start = parse(f[19])
	p.Priority = parseSigned(f[15])
	p.Nice = parseSigned(f[16])
	p.Processor = parseSigned(f[36])
	p.Policy = parse(f[38])
	if p.Start == 0 {
		return p, errors.New("invalid starttime")
	}
	status, err := os.Open(filepath.Join(base, "status"))
	if err == nil {
		scan := bufio.NewScanner(status)
		for scan.Scan() {
			k, v, ok := strings.Cut(scan.Text(), ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			fields := strings.Fields(v)
			switch k {
			case "Threads":
				p.Threads = parse(v)
			case "VmRSS":
				if len(fields) > 0 {
					p.RSS = parse(fields[0]) * 1024
				}
			case "Cpus_allowed_list":
				p.Allowed = v
			case "voluntary_ctxt_switches":
				p.Voluntary = Metric{parse(v), true}
			case "nonvoluntary_ctxt_switches":
				p.Involuntary = Metric{parse(v), true}
			}
		}
		status.Close()
	}
	sched, err := os.ReadFile(filepath.Join(base, "schedstat"))
	if err == nil {
		f := strings.Fields(string(sched))
		if len(f) >= 3 {
			p.Runtime = Metric{parse(f[0]), true}
			p.Wait = Metric{parse(f[1]), true}
			p.Schedules = Metric{parse(f[2]), true}
		}
	}
	ioFile, err := os.Open(filepath.Join(base, "io"))
	if err == nil {
		scan := bufio.NewScanner(ioFile)
		for scan.Scan() {
			k, v, ok := strings.Cut(scan.Text(), ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch k {
			case "read_bytes":
				p.Read = Metric{parse(v), true}
			case "write_bytes":
				p.Write = Metric{parse(v), true}
			}
		}
		ioFile.Close()
	}
	w, err := os.ReadFile(filepath.Join(base, "wchan"))
	if err == nil {
		p.WChan = strings.TrimSpace(string(w))
	}
	return p, nil
}
func parse(s string) uint64      { v, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64); return v }
func parseSigned(s string) int64 { v, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return v }
func diff(a, b Metric) Delta {
	if !a.Available || !b.Available || b.Value < a.Value {
		return Delta{}
	}
	return Delta{b.Value - a.Value, true}
}
func compare(a, b Snapshot) Report {
	sec := b.At.Sub(a.At).Seconds()
	if sec <= 0 {
		sec = 0.000001
	}
	out := Report{Time: b.At, IntervalSeconds: sec, Scanned: b.Scanned, Skipped: b.Skipped, Matched: len(b.Items), Records: make([]Record, 0, len(b.Items))}
	for k, p := range b.Items {
		old, ok := a.Items[k]
		if !ok {
			continue
		}
		r := Record{Sample: p, CPU: diff(old.Runtime, p.Runtime), Wait: diff(old.Wait, p.Wait), Schedules: diff(old.Schedules, p.Schedules), Read: diff(old.Read, p.Read), Write: diff(old.Write, p.Write), Voluntary: diff(old.Voluntary, p.Voluntary), Involuntary: diff(old.Involuntary, p.Involuntary)}
		if r.CPU.Available {
			r.CPUPercent = float64(r.CPU.Value) / 1e9 / sec * 100
		}
		if r.Wait.Available {
			r.WaitPercent = float64(r.Wait.Value) / 1e9 / sec * 100
		}
		if r.Read.Available {
			r.ReadBPS = float64(r.Read.Value) / sec
		}
		if r.Write.Available {
			r.WriteBPS = float64(r.Write.Value) / sec
		}
		if r.Voluntary.Available && r.Involuntary.Available {
			r.CtxPS = float64(r.Voluntary.Value+r.Involuntary.Value) / sec
		}
		if r.CPU.Available && r.Wait.Available && r.CPU.Value > 0 {
			r.WaitToRun = float64(r.Wait.Value) / float64(r.CPU.Value)
			r.RatioValid = true
		}
		out.Records = append(out.Records, r)
	}
	return out
}
func sortRecords(rows []Record, by string) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		var x, y float64
		switch by {
		case "wait":
			x, y = a.WaitPercent, b.WaitPercent
			x, y = a.ReadBPS+a.WriteBPS, b.ReadBPS+b.WriteBPS
		case "ctx":
			x, y = a.CtxPS, b.CtxPS
		case "sched":
			x, y = float64(a.Schedules.Value), float64(b.Schedules.Value)
		case "rss":
			x, y = float64(a.Sample.RSS), float64(b.Sample.RSS)
		case "pid":
			return a.Sample.PID < b.Sample.PID
		default:
			x, y = a.CPUPercent, b.CPUPercent
		}
		if x != y {
			return x > y
		}
		return a.Sample.PID < b.Sample.PID
	})
}
func render(r Report, c Config) {
	width := 116
	line := strings.Repeat("─", width)
	host, _ := os.Hostname()
	if host == "" {
		host = "linux"
	}
	mode := "SNAPSHOT"
	if c.Watch {
		mode = "LIVE"
	}
	fmt.Println("\033[1;36m" + strings.Repeat("═", width) + "\033[0m")
	fmt.Printf("\033[1;36m  N I X\033[0m  \033[2m/ Linux Scheduler Forensics\033[0m%*s\n", 50, "v2.1")
	fmt.Printf("  %-27s  %-26s  %-20s  %s\n", "HOST  "+host, "MODE  "+mode, "INTERVAL  "+fmt.Sprintf("%.2fs", r.IntervalSeconds), r.Time.Format("15:04:05"))
	fmt.Println(line)
	fmt.Printf("  SCANNED  \033[1m%d\033[0m     SKIPPED  \033[1m%d\033[0m     MATCHED  \033[1m%d\033[0m     COMPARED  \033[1m%d\033[0m\n", r.Scanned, r.Skipped, r.Matched, len(r.Records))
	fmt.Printf("  FILTER   %-25q THREADS  %-8t SORT  %s\n", c.Filter, c.Threads, strings.ToUpper(c.Sort))
	fmt.Println("\033[2m  CPU and WAIT use one-core percentages; WAIT is runnable queue delay, not sleep time.\033[0m")
	show("CPU ACTIVITY", r.Records, c, "cpu")
	show("SCHEDULER CONTENTION", r.Records, c, "wait")
	show("DISK I/O", r.Records, c, "io")
	show("CONTEXT SWITCHING", r.Records, c, "ctx")
	fmt.Println("\033[2m" + line + "\033[0m")
	fmt.Println("  N/A = inaccessible or unavailable counter  |  Rates are per second  |  Ctrl+C to exit")
}
func show(title string, rows []Record, c Config, by string) {
	copyRows := append([]Record(nil), rows...)
	sortRecords(copyRows, by)
	fmt.Printf("\n\033[1;36m  %s\033[0m\n", title)
	fmt.Printf("  %-7s %-6s %-19s %-5s %7s %7s %9s %9s %8s %7s %5s %-8s %s\n", "PID", "TGID", "PROCESS", "ST", "CPU%", "WAIT%", "READ/s", "WRITE/s", "CTX/s", "SCHED", "NICE", "POLICY", "WAIT CHANNEL")
	fmt.Println("  " + strings.Repeat("─", 112))
	count := 0
	for _, p := range copyRows {
		if count >= c.Limit {
			break
		}
		switch by {
		case "cpu":
			if !p.CPU.Available || p.CPU.Value == 0 {
				continue
			}
		case "wait":
			if !p.Wait.Available || p.Wait.Value == 0 {
				continue
			}
		case "io":
			if (!p.Read.Available || p.Read.Value == 0) && (!p.Write.Available || p.Write.Value == 0) {
				continue
			}
		case "ctx":
			if p.CtxPS == 0 {
				continue
			}
		}
		name := p.Sample.Name
		w := p.Sample.WChan
		if w == "" || w == "0" {
			w = "-"
		}
		if !c.Wide {
			name = short(name, 19)
			w = short(w, 22)
		}
		fmt.Printf("  %-7d %-6d %-19s %-5s %7s %7s %9s %9s %8s %7s %5d %-8s %s\n", p.Sample.PID, p.Sample.TGID, name, p.Sample.State, percent(p.CPU, p.CPUPercent), percent(p.Wait, p.WaitPercent), rate(p.Read, p.ReadBPS), rate(p.Write, p.WriteBPS), ctxRate(p), deltaStr(p.Schedules), p.Sample.Nice, policy(p.Sample.Policy), w)
		if c.Wide {
			fmt.Printf("    affinity=%s  priority=%d", p.Sample.Allowed, p.Sample.Priority)
			if p.RatioValid {
				fmt.Printf("  wait/run=%.3f", p.WaitToRun)
			}
			fmt.Println()
		}
		count++
	}
	if count == 0 {
		fmt.Println("  No measurable activity in this category during the sample.")
	}
}
func short(s string, n int) string {
	v := []rune(s)
	if len(v) <= n {
		return s
	}
	return string(v[:n-3]) + "..."
}
func percent(d Delta, v float64) string {
	if !d.Available {
		return "N/A"
	}
	return fmt.Sprintf("%.1f", v)
}
func rate(d Delta, v float64) string {
	if !d.Available {
		return "N/A"
	}
	return fmt.Sprintf("%.1fK", v/1024)
}
func deltaStr(d Delta) string {
	if !d.Available {
		return "N/A"
	}
	return strconv.FormatUint(d.Value, 10)
}
func ctxRate(r Record) string {
	if !r.Voluntary.Available || !r.Involuntary.Available {
		return "N/A"
	}
	return fmt.Sprintf("%.1f", r.CtxPS)
}
func policy(n uint64) string {
	switch n {
	case 0:
		return "OTHER"
	case 1:
		return "FIFO"
	case 2:
		return "RR"
	case 3:
		return "BATCH"
	case 5:
		return "IDLE"
	case 6:
		return "DEADLINE"
	case 7:
		return "EXT"
	default:
		return fmt.Sprintf("POLICY-%d", n)
	}
}
