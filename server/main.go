package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/docker/docker/api/types"
	containerTypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

const (
	defaultPort      = "8080"
	defaultStaticDir = "../dist"
)

type SystemMetrics struct {
	Timestamp      time.Time   `json:"timestamp"`
	UptimeSeconds  uint64      `json:"uptime_seconds"`
	CPUUsage       float64     `json:"cpu_usage"`
	CPUTemperature float64     `json:"cpu_temperature"`
	RAMUsage       float64     `json:"ram_usage_percent"`
	RAMUsedGB      float64     `json:"ram_used_gb"`
	RAMTotalGB     float64     `json:"ram_total_gb"`
	Network        NetworkIO   `json:"network"`
	Alerts         []AlertItem `json:"alerts"`
}

type NetworkIO struct {
	DownloadMbps float64 `json:"download_mbps"`
	UploadMbps   float64 `json:"upload_mbps"`
	LatencyMS    float64 `json:"latency_ms"`
}

type StorageUnit struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Mountpoint   string  `json:"mountpoint"`
	UsagePercent float64 `json:"usage_percent"`
	UsedGB       float64 `json:"used_gb"`
	TotalGB      float64 `json:"total_gb"`
	Temperature  float64 `json:"temperature"`
	ReadIOPS     int     `json:"read_iops"`
	WriteIOPS    int     `json:"write_iops"`
	Status       string  `json:"status"`
}

type DockerContainer struct {
	Name                string  `json:"name"`
	Status              string  `json:"status"`
	Image               string  `json:"image"`
	CPUUsagePercent     float64 `json:"cpu_usage_percent"`
	MemoryUsagePercent  float64 `json:"memory_usage_percent"`
	RestartCount        int     `json:"restart_count"`
	LastStateChangeUnix int64   `json:"last_state_change_unix"`
}

type AlertItem struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

type collector struct {
	start       time.Time
	netTracker  *netRateTracker
	diskTracker *diskRateTracker
	dockerCli   *client.Client
}

type netRateTracker struct {
	mu       sync.Mutex
	last     *net.IOCountersStat
	lastTime time.Time
}

type diskRateTracker struct {
	mu       sync.Mutex
	last     map[string]disk.IOCountersStat
	lastTime time.Time
}

func newCollector() *collector {
	var cli *client.Client
	if c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation()); err == nil {
		cli = c
	} else {
		log.Printf("docker client unavailable: %v", err)
	}

	return &collector{
		start:       time.Now(),
		netTracker:  &netRateTracker{},
		diskTracker: &diskRateTracker{last: make(map[string]disk.IOCountersStat)},
		dockerCli:   cli,
	}
}

func main() {
	port := getenv("FNOS_MONITOR_PORT", defaultPort)
	staticDir := getenv("FNOS_MONITOR_STATIC", defaultStaticDir)

	staticDir, _ = filepath.Abs(staticDir)
	if _, err := os.Stat(staticDir); err != nil {
		log.Printf("warning: static directory %s not accessible: %v", staticDir, err)
	}

	coll := newCollector()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/system", func(w http.ResponseWriter, r *http.Request) {
		metrics, err := coll.collectSystem(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, metrics)
	})

	mux.HandleFunc("/api/storage", func(w http.ResponseWriter, r *http.Request) {
		storage, err := coll.collectStorage(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, storage)
	})

	mux.HandleFunc("/api/docker", func(w http.ResponseWriter, r *http.Request) {
		containers, err := coll.collectContainers(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, containers)
	})

	mux.HandleFunc("/api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	fileServer := http.FileServer(http.Dir(staticDir))
	mux.Handle("/", fileServer)

	addr := ":" + port
	log.Printf("fnos-monitor backend listening on %s (static %s)", addr, staticDir)
	if err := http.ListenAndServe(addr, withLogging(withCORS(mux))); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}

func (c *collector) collectSystem(ctx context.Context) (SystemMetrics, error) {
	vmStat, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return SystemMetrics{}, err
	}

	cpuPercents, err := cpu.PercentWithContext(ctx, 0, false)
	if err != nil {
		return SystemMetrics{}, err
	}

	hostInfo, err := host.InfoWithContext(ctx)
	if err != nil {
		return SystemMetrics{}, err
	}

	var cpuTemp = math.NaN()
	if temps, err := host.SensorsTemperaturesWithContext(ctx); err == nil {
		cpuTemp = pickCPUTemperature(temps)
	}

	downloadMbps, uploadMbps := c.netTracker.compute(ctx)
	latency := measureLatency()

	metrics := SystemMetrics{
		Timestamp:      time.Now().UTC(),
		UptimeSeconds:  hostInfo.Uptime,
		CPUUsage:       firstOrZero(cpuPercents),
		CPUTemperature: cpuTemp,
		RAMUsage:       vmStat.UsedPercent,
		RAMUsedGB:      bytesToGB(vmStat.Used),
		RAMTotalGB:     bytesToGB(vmStat.Total),
		Network: NetworkIO{
			DownloadMbps: downloadMbps,
			UploadMbps:   uploadMbps,
			LatencyMS:    latency,
		},
	}

	if metrics.CPUUsage > 85 {
		metrics.Alerts = append(metrics.Alerts, AlertItem{Level: "warning", Message: "CPU 负载较高"})
	}
	if !math.IsNaN(cpuTemp) && cpuTemp > 85 {
		metrics.Alerts = append(metrics.Alerts, AlertItem{Level: "warning", Message: "CPU 温度偏高"})
	}

	return metrics, nil
}

func (c *collector) collectStorage(ctx context.Context) ([]StorageUnit, error) {
	partitions, err := disk.PartitionsWithContext(ctx, true)
	if err != nil {
		return nil, err
	}

	ioCounters, _ := disk.IOCountersWithContext(ctx)
	temps := temperatureLookup(ctx)

	type agg struct {
		unit StorageUnit
	}

	groups := make(map[string]*StorageUnit)

	for _, part := range partitions {
		if shouldIgnoreFilesystem(part.Fstype) || shouldIgnoreMount(part.Mountpoint) {
			continue
		}
		devKey := canonicalDevice(part.Device)
		if devKey == "" {
			continue
		}

		usage, err := disk.UsageWithContext(ctx, part.Mountpoint)
		if err != nil || usage.Total == 0 {
			continue
		}

		unit, exists := groups[devKey]
		if !exists {
			unit = &StorageUnit{
				ID:         devKey,
				Name:       part.Device,
				Mountpoint: part.Mountpoint,
				Status:     "ONLINE",
			}
			groups[devKey] = unit
		} else {
			choice := choosePreferredMount(unit.Mountpoint, part.Mountpoint)
			unit.Mountpoint = choice
		}

		unit.TotalGB += bytesToGB(usage.Total)
		unit.UsedGB += bytesToGB(usage.Used)
	}

	results := make([]StorageUnit, 0, len(groups))
	for devKey, unit := range groups {
		if unit.TotalGB > 0 {
			unit.UsagePercent = (unit.UsedGB / unit.TotalGB) * 100
		}

		if unit.Mountpoint == "" {
			unit.Mountpoint = "/"
		}

		if unit.UsagePercent > 90 {
			unit.Status = "FULL"
		}

		if temp, ok := temps[devKey]; ok {
			unit.Temperature = temp
		}

		readIOPS, writeIOPS := c.diskTracker.compute(devKey, ioCounters)
		unit.ReadIOPS = readIOPS
		unit.WriteIOPS = writeIOPS

		results = append(results, *unit)
	}

	filtered := filterVolumeMounts(results)
	if len(filtered) == 0 {
		return results, nil
	}
	return filtered, nil
}

func (c *collector) collectContainers(ctx context.Context) ([]DockerContainer, error) {
	if c.dockerCli == nil {
		return nil, errors.New("docker daemon不可用或未启用")
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	containers, err := c.dockerCli.ContainerList(ctx, containerTypes.ListOptions{All: true})
	if err != nil {
		return nil, err
	}

	results := make([]DockerContainer, 0, len(containers))
	for _, ctr := range containers {
		inspect, inspectErr := c.inspectContainer(ctx, ctr.ID)
		if inspectErr != nil {
			log.Printf("warn: inspect %s: %v", ctr.ID[:12], inspectErr)
		}

		stats, statsErr := c.fetchContainerStats(ctx, ctr.ID)
		if statsErr != nil {
			log.Printf("warn: container stats %s: %v", ctr.Names, statsErr)
		}

		name := ctr.ID[:12]
		if len(ctr.Names) > 0 {
			name = strings.TrimLeft(ctr.Names[0], "/")
		}

		status := ctr.State
		if status == "" {
			status = ctr.Status
		}

		restartCount := 0
		lastChange := stats.updated
		if inspect != nil && inspect.State != nil {
			if inspect.State.Status != "" {
				status = inspect.State.Status
			}
			restartCount = inspect.RestartCount
			if t, err := time.Parse(time.RFC3339Nano, inspect.State.StartedAt); err == nil {
				lastChange = t.Unix()
			}
		}

		results = append(results, DockerContainer{
			Name:                name,
			Status:              status,
			Image:               ctr.Image,
			CPUUsagePercent:     stats.cpu,
			MemoryUsagePercent:  stats.mem,
			RestartCount:        restartCount,
			LastStateChangeUnix: lastChange,
		})
	}

	return results, nil
}

func (c *collector) fetchContainerStats(ctx context.Context, id string) (containerStatResult, error) {
	if c.dockerCli == nil {
		return containerStatResult{}, errors.New("docker not available")
	}

	statsCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	resp, err := c.dockerCli.ContainerStats(statsCtx, id, false)
	if err != nil {
		return containerStatResult{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return containerStatResult{}, err
	}

	var stats types.StatsJSON
	if err := json.Unmarshal(body, &stats); err != nil {
		return containerStatResult{}, err
	}

	return containerStatResult{
		cpu:     calculateCPUPercent(stats),
		mem:     calculateMemPercent(stats),
		updated: stats.Read.Unix(),
	}, nil
}

func (c *collector) inspectContainer(ctx context.Context, id string) (*types.ContainerJSON, error) {
	if c.dockerCli == nil {
		return nil, errors.New("docker not available")
	}
	inspectCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	info, err := c.dockerCli.ContainerInspect(inspectCtx, id)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

type containerStatResult struct {
	cpu, mem float64
	updated  int64
}

func calculateCPUPercent(stats types.StatsJSON) float64 {
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)
	if cpuDelta <= 0 || systemDelta <= 0 {
		return 0
	}
	onlineCPUs := float64(stats.CPUStats.OnlineCPUs)
	if onlineCPUs == 0 {
		onlineCPUs = float64(len(stats.CPUStats.CPUUsage.PercpuUsage))
		if onlineCPUs == 0 {
			onlineCPUs = 1
		}
	}
	return (cpuDelta / systemDelta) * onlineCPUs * 100
}

func calculateMemPercent(stats types.StatsJSON) float64 {
	if stats.MemoryStats.Limit == 0 {
		return 0
	}
	return float64(stats.MemoryStats.Usage) / float64(stats.MemoryStats.Limit) * 100
}

func (t *netRateTracker) compute(ctx context.Context) (float64, float64) {
	stats, err := net.IOCountersWithContext(ctx, false)
	if err != nil || len(stats) == 0 {
		return 0, 0
	}
	current := stats[0]

	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	if t.last == nil {
		t.last = &current
		t.lastTime = now
		return 0, 0
	}

	deltaSeconds := now.Sub(t.lastTime).Seconds()
	if deltaSeconds <= 0 {
		return 0, 0
	}

	down := float64(current.BytesRecv-t.last.BytesRecv) * 8 / 1_000_000 / deltaSeconds
	up := float64(current.BytesSent-t.last.BytesSent) * 8 / 1_000_000 / deltaSeconds

	t.last = &current
	t.lastTime = now
	return down, up
}

func (d *diskRateTracker) compute(device string, counters map[string]disk.IOCountersStat) (int, int) {
	stat, ok := counters[device]
	if !ok {
		return 0, 0
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	if d.lastTime.IsZero() || len(d.last) == 0 {
		d.last[device] = stat
		d.lastTime = now
		return 0, 0
	}

	prev, ok := d.last[device]
	if !ok {
		d.last[device] = stat
		return 0, 0
	}

	deltaSeconds := now.Sub(d.lastTime).Seconds()
	if deltaSeconds <= 0 {
		return 0, 0
	}

	readIOPS := int(float64(stat.ReadCount-prev.ReadCount) / deltaSeconds)
	writeIOPS := int(float64(stat.WriteCount-prev.WriteCount) / deltaSeconds)

	d.last[device] = stat
	d.lastTime = now
	return readIOPS, writeIOPS
}

func pickCPUTemperature(temps []host.TemperatureStat) float64 {
	var sum float64
	var count int
	for _, t := range temps {
		key := strings.ToLower(t.SensorKey)
		if strings.Contains(key, "cpu") || strings.Contains(key, "package_id") {
			sum += t.Temperature
			count++
		}
	}
	if count == 0 {
		return math.NaN()
	}
	return sum / float64(count)
}

func temperatureLookup(ctx context.Context) map[string]float64 {
	result := make(map[string]float64)
	temps, err := host.SensorsTemperaturesWithContext(ctx)
	if err != nil {
		return result
	}
	for _, t := range temps {
		key := canonicalDevice(t.SensorKey)
		if key != "" {
			result[key] = t.Temperature
		}
	}
	return result
}

func canonicalDevice(dev string) string {
	if dev == "" {
		return ""
	}
	base := filepath.Base(dev)
	base = strings.TrimPrefix(base, "/dev/")
	if strings.HasPrefix(base, "nvme") {
		if idx := strings.LastIndex(base, "p"); idx > 0 {
			return base[:idx]
		}
		return base
	}
	return strings.TrimRightFunc(base, func(r rune) bool {
		return unicode.IsDigit(r)
	})
}

func choosePreferredMount(current, candidate string) string {
	if candidate == "" {
		return current
	}
	if current == "" {
		return candidate
	}

	candidate = normalizeVolumeMount(candidate)
	current = normalizeVolumeMount(current)

	if matchesVolumeRoot(candidate) && !matchesVolumeRoot(current) {
		return candidate
	}
	if matchesVolumeRoot(current) && !matchesVolumeRoot(candidate) {
		return current
	}
	if candidate == "/" {
		return current
	}
	if len(candidate) < len(current) || current == "" {
		return candidate
	}
	return current
}

func normalizeVolumeMount(path string) string {
	if path == "" {
		return path
	}
	path = strings.TrimRight(path, "/")
	lower := strings.ToLower(path)
	if !strings.HasPrefix(lower, "/vol") {
		return path
	}
	i := len("/vol")
	for i < len(path) && path[i] >= '0' && path[i] <= '9' {
		i++
	}
	return path[:i]
}

func shouldIgnoreFilesystem(fs string) bool {
	fs = strings.ToLower(fs)
	ignored := []string{
		"proc", "sysfs", "tmpfs", "devtmpfs", "devpts", "cgroup", "cgroup2",
		"mqueue", "pstore", "securityfs", "tracefs", "configfs", "debugfs",
		"hugetlbfs", "overlay", "aufs", "efivarfs", "autofs", "rpc_pipefs",
		"fusectl", "fuse.lxcfs", "nsfs", "binfmt_misc",
	}
	for _, ig := range ignored {
		if fs == ig {
			return true
		}
		if strings.HasPrefix(fs, "fuse.") && fs != "fuseblk" {
			return true
		}
	}
	return false
}

func shouldIgnoreMount(mount string) bool {
	if mount == "" {
		return true
	}
	ignoredPrefixes := []string{
		"/proc", "/sys", "/run", "/dev", "/sysroot", "/boot/efi",
		"/var/lib/docker", "/var/lib/containers",
	}
	for _, pre := range ignoredPrefixes {
		if strings.HasPrefix(mount, pre) {
			return true
		}
	}
	return false
}

func filterVolumeMounts(units []StorageUnit) []StorageUnit {
	filtered := make([]StorageUnit, 0, len(units))
	for _, unit := range units {
		lower := strings.ToLower(strings.TrimSuffix(unit.Mountpoint, "/"))
		if matchesVolumeRoot(lower) {
			filtered = append(filtered, unit)
		}
	}
	return filtered
}

func matchesVolumeRoot(mount string) bool {
	if !strings.HasPrefix(mount, "/vol") {
		return false
	}
	suffix := strings.TrimPrefix(mount, "/vol")
	if suffix == "" {
		return true
	}
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func measureLatency() float64 {
	start := time.Now()
	req, err := http.NewRequest("HEAD", "https://1.1.1.1", nil)
	if err != nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)
	client := http.Client{Timeout: 500 * time.Millisecond}
	if _, err := client.Do(req); err != nil {
		return 0
	}
	return float64(time.Since(start).Milliseconds())
}

func writeJSON(w http.ResponseWriter, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func bytesToGB(v uint64) float64 {
	return float64(v) / (1024 * 1024 * 1024)
}

func firstOrZero(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	return values[0]
}
