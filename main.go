package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const sampleInterval = time.Second

type Process struct {
	PID              int
	Name             string
	State            string
	Threads          uint64
	RSS              uint64
	ReadBytes        uint64
	WriteBytes       uint64
	Runtime          uint64
	WaitTime         uint64
	Schedules        uint64
	VoluntaryCtx     uint64
	InvoluntaryCtx   uint64
	WChan            string
}

type Activity struct {
	PID            int
	Name           string
	State          string
	Threads        uint64
	RSS            uint64
	CPUTime        uint64
	WaitTime       uint64
	Schedules      uint64
	ReadBytes      uint64
	WriteBytes     uint64
	VoluntaryCtx   uint64
	InvoluntaryCtx uint64
	WChan          string
	Score          float64
}

func main() {
	fmt.Println("procwave - Linux process activity explorer")
	fmt.Printf("Sampling /proc for %s...\n\n", sampleInterval)

	first := snapshot()

	time.Sleep(sampleInterval)

	second := snapshot()

	activities := calculateActivity(first, second)

	printSystemSummary(activities)
	printActiveProcesses(activities, 20)
	printWaitingProcesses(activities, 15)
	printIOProcesses(activities, 15)
}

func snapshot() map[int]Process {
	result := make(map[int]Process)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		fail(err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		process, err := readProcess(pid)
		if err != nil {
			continue
		}

		result[pid] = process
	}

	return result
}

func readProcess(pid int) (Process, error) {
	process := Process{
		PID: pid,
	}

	if err := readStatus(&process); err != nil {
		return Process{}, err
	}

	readScheduler(&process)
	readIO(&process)
	readWChan(&process)

	return process, nil
}

func readStatus(process *Process) error {
	path := fmt.Sprintf("/proc/%d/status", process.PID)

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		value = strings.TrimSpace(value)

		switch key {
		case "Name":
			process.Name = value

		case "State":
			fields := strings.Fields(value)
			if len(fields) > 0 {
				process.State = fields[0]
			}

		case "Threads":
			process.Threads = parseUint(value)

		case "VmRSS":
			fields := strings.Fields(value)
			if len(fields) > 0 {
				process.RSS = parseUint(fields[0]) * 1024
			}

		case "voluntary_ctxt_switches":
			process.VoluntaryCtx = parseUint(value)

		case "nonvoluntary_ctxt_switches":
			process.InvoluntaryCtx = parseUint(value)
		}
	}

	return scanner.Err()
}

func readScheduler(process *Process) {
	path := fmt.Sprintf("/proc/%d/schedstat", process.PID)

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	fields := strings.Fields(string(data))

	if len(fields) < 3 {
		return
	}

	process.Runtime = parseUint(fields[0])
	process.WaitTime = parseUint(fields[1])
	process.Schedules = parseUint(fields[2])
}

func readIO(process *Process) {
	path := fmt.Sprintf("/proc/%d/io", process.PID)

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}

		value = strings.TrimSpace(value)

		switch key {
		case "read_bytes":
			process.ReadBytes = parseUint(value)

		case "write_bytes":
			process.WriteBytes = parseUint(value)
		}
	}
}

func readWChan(process *Process) {
	path := fmt.Sprintf("/proc/%d/wchan", process.PID)

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	value := strings.TrimSpace(string(data))

	if value != "" && value != "0" {
		process.WChan = value
	}
}

func calculateActivity(
	first map[int]Process,
	second map[int]Process,
) []Activity {
	activities := make([]Activity, 0, len(second))

	for pid, current := range second {
		previous, exists := first[pid]
		if !exists {
			continue
		}

		cpu := delta(current.Runtime, previous.Runtime)
		wait := delta(current.WaitTime, previous.WaitTime)
		schedules := delta(current.Schedules, previous.Schedules)
		readBytes := delta(current.ReadBytes, previous.ReadBytes)
		writeBytes := delta(current.WriteBytes, previous.WriteBytes)
		voluntary := delta(current.VoluntaryCtx, previous.VoluntaryCtx)
		involuntary := delta(
			current.InvoluntaryCtx,
			previous.InvoluntaryCtx,
		)

		score :=
			float64(cpu)/1e6 +
				float64(wait)/2e6 +
				float64(readBytes+writeBytes)/(1024*1024) +
				float64(schedules)/10 +
				float64(involuntary)

		activities = append(activities, Activity{
			PID:            pid,
			Name:           current.Name,
			State:          current.State,
			Threads:        current.Threads,
			RSS:            current.RSS,
			CPUTime:        cpu,
			WaitTime:       wait,
			Schedules:      schedules,
			ReadBytes:      readBytes,
			WriteBytes:     writeBytes,
			VoluntaryCtx:   voluntary,
			InvoluntaryCtx: involuntary,
			WChan:          current.WChan,
			Score:          score,
		})
	}

	return activities
}

func printSystemSummary(activities []Activity) {
	var running int
	var sleeping int
	var blocked int
	var zombie int
	var threads uint64
	var memory uint64

	for _, process := range activities {
		threads += process.Threads
		memory += process.RSS

		switch process.State {
		case "R":
			running++
		case "S", "I":
			sleeping++
		case "D":
			blocked++
		case "Z":
			zombie++
		}
	}

	fmt.Println("SYSTEM SNAPSHOT")
	fmt.Printf("  Processes:       %d\n", len(activities))
	fmt.Printf("  Threads:         %d\n", threads)
	fmt.Printf("  Running:         %d\n", running)
	fmt.Printf("  Sleeping:        %d\n", sleeping)
	fmt.Printf("  I/O blocked:     %d\n", blocked)
	fmt.Printf("  Zombies:         %d\n", zombie)
	fmt.Printf("  Process RSS:     %s\n", humanBytes(memory))
	fmt.Println()
}

func printActiveProcesses(activities []Activity, limit int) {
	processes := append([]Activity(nil), activities...)

	sort.Slice(processes, func(i, j int) bool {
		return processes[i].Score > processes[j].Score
	})

	fmt.Println("MOST ACTIVE")

	fmt.Printf(
		"%-7s %-20s %10s %10s %8s %10s %s\n",
		"PID",
		"PROCESS",
		"CPU",
		"WAIT",
		"SCHED",
		"RSS",
		"WCHAN",
	)

	printed := 0

	for _, process := range processes {
		if process.Score == 0 {
			continue
		}

		fmt.Printf(
			"%-7d %-20s %10s %10s %8d %10s %s\n",
			process.PID,
			shorten(process.Name, 20),
			durationNS(process.CPUTime),
			durationNS(process.WaitTime),
			process.Schedules,
			humanBytes(process.RSS),
			shorten(process.WChan, 30),
		)

		printed++

		if printed >= limit {
			break
		}
	}

	if printed == 0 {
		fmt.Println("No measurable activity during sample.")
	}

	fmt.Println()
}

func printWaitingProcesses(activities []Activity, limit int) {
	processes := append([]Activity(nil), activities...)

	sort.Slice(processes, func(i, j int) bool {
		return processes[i].WaitTime > processes[j].WaitTime
	})

	fmt.Println("SCHEDULER WAIT")

	fmt.Printf(
		"%-7s %-20s %12s %12s %10s\n",
		"PID",
		"PROCESS",
		"CPU",
		"WAIT",
		"WAIT/CPU",
	)

	printed := 0

	for _, process := range processes {
		if process.WaitTime == 0 {
			continue
		}

		ratio := 0.0

		if process.CPUTime > 0 {
			ratio =
				float64(process.WaitTime) /
					float64(process.CPUTime) *
					100
		}

		fmt.Printf(
			"%-7d %-20s %12s %12s %9.1f%%\n",
			process.PID,
			shorten(process.Name, 20),
			durationNS(process.CPUTime),
			durationNS(process.WaitTime),
			ratio,
		)

		printed++

		if printed >= limit {
			break
		}
	}

	if printed == 0 {
		fmt.Println("No scheduler waiting detected.")
	}

	fmt.Println()
}

func printIOProcesses(activities []Activity, limit int) {
	processes := append([]Activity(nil), activities...)

	sort.Slice(processes, func(i, j int) bool {
		left := processes[i].ReadBytes + processes[i].WriteBytes
		right := processes[j].ReadBytes + processes[j].WriteBytes

		return left > right
	})

	fmt.Println("DISK I/O")

	fmt.Printf(
		"%-7s %-20s %14s %14s\n",
		"PID",
		"PROCESS",
		"READ",
		"WRITE",
	)

	printed := 0

	for _, process := range processes {
		if process.ReadBytes == 0 && process.WriteBytes == 0 {
			continue
		}

		fmt.Printf(
			"%-7d %-20s %14s %14s\n",
			process.PID,
			shorten(process.Name, 20),
			humanBytes(process.ReadBytes),
			humanBytes(process.WriteBytes),
		)

		printed++

		if printed >= limit {
			break
		}
	}

	if printed == 0 {
		fmt.Println("No physical disk I/O detected during sample.")
	}

	fmt.Println()
}

func delta(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}

	return current - previous
}

func parseUint(value string) uint64 {
	result, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}

	return result
}

func durationNS(value uint64) string {
	duration := time.Duration(value)

	switch {
	case duration >= time.Second:
		return fmt.Sprintf("%.2fs", duration.Seconds())

	case duration >= time.Millisecond:
		return fmt.Sprintf(
			"%.2fms",
			float64(duration)/float64(time.Millisecond),
		)

	case duration >= time.Microsecond:
		return fmt.Sprintf(
			"%.2fµs",
			float64(duration)/float64(time.Microsecond),
		)

	default:
		return fmt.Sprintf("%dns", value)
	}
}

func humanBytes(value uint64) string {
	const (
		KiB = 1024
		MiB = 1024 * KiB
		GiB = 1024 * MiB
		TiB = 1024 * GiB
	)

	switch {
	case value >= TiB:
		return fmt.Sprintf(
			"%.2fTiB",
			float64(value)/float64(TiB),
		)

	case value >= GiB:
		return fmt.Sprintf(
			"%.2fGiB",
			float64(value)/float64(GiB),
		)

	case value >= MiB:
		return fmt.Sprintf(
			"%.2fMiB",
			float64(value)/float64(MiB),
		)

	case value >= KiB:
		return fmt.Sprintf(
			"%.2fKiB",
			float64(value)/float64(KiB),
		)

	default:
		return fmt.Sprintf("%dB", value)
	}
}

func shorten(value string, width int) string {
	if value == "" {
		return "-"
	}

	runes := []rune(value)

	if len(runes) <= width {
		return value
	}

	if width <= 3 {
		return string(runes[:width])
	}

	return string(runes[:width-3]) + "..."
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
