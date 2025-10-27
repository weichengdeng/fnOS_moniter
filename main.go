package main

import (
    "bufio"
    "errors"
    "flag"
    "fmt"
    "io/fs"
    "os"
    "path/filepath"
    "runtime"
    "sort"
    "strconv"
    "strings"
    "syscall"
    "time"
)

type cpuTimes struct {
    idle  uint64
    total uint64
}

// readCPUTimes reads aggregate CPU times from /proc/stat (Linux only)
func readCPUTimes() (cpuTimes, error) {
    f, err := os.Open("/proc/stat")
    if err != nil {
        return cpuTimes{}, err
    }
    defer f.Close()
    sc := bufio.NewScanner(f)
    for sc.Scan() {
        line := sc.Text()
        if strings.HasPrefix(line, "cpu ") { // aggregate
            fields := strings.Fields(line)[1:]
            if len(fields) < 5 {
                return cpuTimes{}, errors.New("unexpected /proc/stat format")
            }
            var vals []uint64
            for _, s := range fields {
                v, err := strconv.ParseUint(s, 10, 64)
                if err != nil {
                    return cpuTimes{}, err
                }
                vals = append(vals, v)
            }
            // total = sum(all)
            var total uint64
            for _, v := range vals {
                total += v
            }
            idle := vals[3] // idle
            return cpuTimes{idle: idle, total: total}, nil
        }
    }
    if err := sc.Err(); err != nil {
        return cpuTimes{}, err
    }
    return cpuTimes{}, errors.New("cpu line not found in /proc/stat")
}

func cpuUsagePercent(prev, cur cpuTimes) float64 {
    dt := float64(cur.total - prev.total)
    if dt <= 0 {
        return 0
    }
    didle := float64(cur.idle - prev.idle)
    usage := (1.0 - didle/dt) * 100.0
    if usage < 0 {
        usage = 0
    }
    if usage > 100 {
        usage = 100
    }
    return usage
}

// readMem reads MemTotal and MemAvailable from /proc/meminfo (kB)
func readMem() (totalKB, availKB uint64, err error) {
    f, err := os.Open("/proc/meminfo")
    if err != nil {
        return 0, 0, err
    }
    defer f.Close()
    sc := bufio.NewScanner(f)
    for sc.Scan() {
        line := sc.Text()
        if strings.HasPrefix(line, "MemTotal:") {
            fields := strings.Fields(line)
            if len(fields) >= 2 {
                v, _ := strconv.ParseUint(fields[1], 10, 64)
                totalKB = v
            }
        } else if strings.HasPrefix(line, "MemAvailable:") {
            fields := strings.Fields(line)
            if len(fields) >= 2 {
                v, _ := strconv.ParseUint(fields[1], 10, 64)
                availKB = v
            }
        }
    }
    if err := sc.Err(); err != nil {
        return 0, 0, err
    }
    if totalKB == 0 {
        return 0, 0, errors.New("MemTotal not found")
    }
    return totalKB, availKB, nil
}

// statFS returns disk space for a mount point using syscall.Statfs
func statFS(path string) (total, used, free uint64, err error) {
    var st syscall.Statfs_t
    if err := syscall.Statfs(path, &st); err != nil {
        return 0, 0, 0, err
    }
    bsize := uint64(st.Bsize)
    total = st.Blocks * bsize
    free = st.Bavail * bsize
    used = total - free
    return
}

// listBlockDevices returns base block device names from /sys/block
func listBlockDevices() ([]string, error) {
    entries, err := os.ReadDir("/sys/block")
    if err != nil {
        return nil, err
    }
    out := make([]string, 0, len(entries))
    for _, e := range entries {
        name := e.Name()
        if skipBlock(name) {
            continue
        }
        out = append(out, name)
    }
    sort.Strings(out)
    return out, nil
}

func skipBlock(name string) bool {
    // skip loop, ram, zram, dm-*, md*, sr*
    if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "zram") {
        return true
    }
    if strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "md") || strings.HasPrefix(name, "sr") {
        return true
    }
    return false
}

// readDiskStat reads sectors read/written from /sys/block/<dev>/stat and sector size
type diskCounters struct {
    readSectors  uint64
    writeSectors uint64
    sectorSize   uint64
}

func readDiskCounters(dev string) (diskCounters, error) {
    statPath := filepath.Join("/sys/block", dev, "stat")
    data, err := os.ReadFile(statPath)
    if err != nil {
        return diskCounters{}, err
    }
    fields := strings.Fields(string(data))
    if len(fields) < 7 {
        return diskCounters{}, errors.New("unexpected /sys/block/<dev>/stat format")
    }
    // fields: reads completed, reads merged, sectors read, time spent reading,
    //         writes completed, writes merged, sectors written, ...
    rsec, err := strconv.ParseUint(fields[2], 10, 64)
    if err != nil {
        return diskCounters{}, err
    }
    wsec, err := strconv.ParseUint(fields[6], 10, 64)
    if err != nil {
        return diskCounters{}, err
    }
    // sector size
    ssize := uint64(512)
    ssizePath := filepath.Join("/sys/block", dev, "queue", "hw_sector_size")
    if b, err := os.ReadFile(ssizePath); err == nil {
        if v, e := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); e == nil && v > 0 {
            ssize = v
        }
    }
    return diskCounters{readSectors: rsec, writeSectors: wsec, sectorSize: ssize}, nil
}

// listNetIfaces returns network interface names from /sys/class/net excluding virtuals and lo
func listNetIfaces() ([]string, error) {
    entries, err := os.ReadDir("/sys/class/net")
    if err != nil {
        return nil, err
    }
    out := make([]string, 0, len(entries))
    for _, e := range entries {
        name := e.Name()
        if skipIface(name) {
            continue
        }
        out = append(out, name)
    }
    sort.Strings(out)
    return out, nil
}

func skipIface(name string) bool {
    if name == "lo" {
        return true
    }
    for _, p := range []string{"veth", "docker", "br-", "virbr", "vmnet", "tailscale", "wg", "zt", "cilium", "flannel"} {
        if strings.HasPrefix(name, p) {
            return true
        }
    }
    return false
}

type netCounters struct {
    rxBytes uint64
    txBytes uint64
}

// readNetDev reads /proc/net/dev and returns counters by iface
func readNetDev() (map[string]netCounters, error) {
    f, err := os.Open("/proc/net/dev")
    if err != nil {
        return nil, err
    }
    defer f.Close()
    sc := bufio.NewScanner(f)
    // skip first 2 header lines
    for i := 0; i < 2 && sc.Scan(); i++ {
    }
    res := make(map[string]netCounters)
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line == "" {
            continue
        }
        parts := strings.Split(line, ":")
        if len(parts) != 2 {
            continue
        }
        iface := strings.TrimSpace(parts[0])
        fields := strings.Fields(strings.TrimSpace(parts[1]))
        if len(fields) < 16 {
            continue
        }
        rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
        txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
        res[iface] = netCounters{rxBytes: rxBytes, txBytes: txBytes}
    }
    if err := sc.Err(); err != nil {
        return nil, err
    }
    return res, nil
}

// temperature reading
type tempReading struct {
    label string
    c     float64
}

func readThermalZones() ([]tempReading, error) {
    var readings []tempReading
    zones, err := filepath.Glob("/sys/class/thermal/thermal_zone*")
    if err != nil {
        return nil, err
    }
    for _, z := range zones {
        // prefer type or name
        label := filepath.Base(z)
        if b, err := os.ReadFile(filepath.Join(z, "type")); err == nil {
            if s := strings.TrimSpace(string(b)); s != "" {
                label = s
            }
        } else if b, err := os.ReadFile(filepath.Join(z, "name")); err == nil {
            if s := strings.TrimSpace(string(b)); s != "" {
                label = s
            }
        }
        if b, err := os.ReadFile(filepath.Join(z, "temp")); err == nil {
            if v, e := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); e == nil {
                // millidegree C
                readings = append(readings, tempReading{label: label, c: v / 1000.0})
            }
        }
    }
    // hwmon temps
    hwmons, _ := filepath.Glob("/sys/class/hwmon/hwmon*")
    for _, h := range hwmons {
        devName := func() string {
            if b, err := os.ReadFile(filepath.Join(h, "name")); err == nil {
                return strings.TrimSpace(string(b))
            }
            return filepath.Base(h)
        }()
        filepath.WalkDir(h, func(path string, d fs.DirEntry, err error) error {
            if err != nil || d.IsDir() {
                return nil
            }
            base := filepath.Base(path)
            if strings.HasPrefix(base, "temp") && strings.HasSuffix(base, "_input") {
                valb, err := os.ReadFile(path)
                if err != nil {
                    return nil
                }
                v, e := strconv.ParseFloat(strings.TrimSpace(string(valb)), 64)
                if e != nil {
                    return nil
                }
                label := devName
                // try paired label file
                labelPath := strings.TrimSuffix(path, "_input") + "_label"
                if lb, e := os.ReadFile(labelPath); e == nil {
                    ls := strings.TrimSpace(string(lb))
                    if ls != "" {
                        label = devName + ": " + ls
                    }
                }
                readings = append(readings, tempReading{label: label, c: v / 1000.0})
            }
            return nil
        })
    }
    return readings, nil
}

// humanize helpers
func humanBytes(b uint64) string {
    const unit = 1024
    if b < unit {
        return fmt.Sprintf("%d B", b)
    }
    div, exp := uint64(unit), 0
    for n := b / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func humanRate(bps float64) string {
    if bps < 1024 {
        return fmt.Sprintf("%.0f B/s", bps)
    }
    kb := bps / 1024
    if kb < 1024 {
        return fmt.Sprintf("%.1f KiB/s", kb)
    }
    mb := kb / 1024
    if mb < 1024 {
        return fmt.Sprintf("%.1f MiB/s", mb)
    }
    gb := mb / 1024
    return fmt.Sprintf("%.2f GiB/s", gb)
}

func clearScreen() {
    fmt.Print("\033[2J\033[H")
}

func main() {
    if runtime.GOOS != "linux" {
        fmt.Println("该程序用于Linux (fnOS/Debian) 运行；请在Linux上运行或交叉编译后上传运行。")
        return
    }

    interval := flag.Duration("interval", time.Second, "刷新间隔，例如 1s, 2s")
    mount := flag.String("mount", "/", "显示空间使用的挂载点")
    flag.Parse()

    // initial samples for rates
    prevCPU, _ := readCPUTimes()

    // disks
    disks, _ := listBlockDevices()
    prevDisk := make(map[string]diskCounters)
    for _, d := range disks {
        if c, err := readDiskCounters(d); err == nil {
            prevDisk[d] = c
        }
    }

    // net
    ifaces, _ := listNetIfaces()
    prevNet, _ := readNetDev()

    ticker := time.NewTicker(*interval)
    defer ticker.Stop()

    for {
        <-ticker.C

        // CPU
        curCPU, cpuErr := readCPUTimes()
        cpuUsage := 0.0
        if cpuErr == nil {
            cpuUsage = cpuUsagePercent(prevCPU, curCPU)
            prevCPU = curCPU
        }

        // Mem
        memTotalKB, memAvailKB, memErr := readMem()
        var memUsedKB uint64
        var memPct float64
        if memErr == nil {
            memUsedKB = memTotalKB - memAvailKB
            if memTotalKB > 0 {
                memPct = float64(memUsedKB) / float64(memTotalKB) * 100
            }
        }

        // Disk space
        dTotal, dUsed, dFree, dErr := statFS(*mount)

        // Disk IO rates
        diskRates := make([]string, 0)
        curDisks, _ := listBlockDevices()
        for _, d := range curDisks {
            c, err := readDiskCounters(d)
            if err != nil {
                continue
            }
            if p, ok := prevDisk[d]; ok {
                dt := c.sectorSize
                // delta sectors -> bytes
                rbytes := float64((c.readSectors - p.readSectors) * dt)
                wbytes := float64((c.writeSectors - p.writeSectors) * dt)
                // divide by interval seconds
                sec := interval.Seconds()
                if sec <= 0 {
                    sec = 1
                }
                diskRates = append(diskRates, fmt.Sprintf("%s: R %s  W %s", d, humanRate(rbytes/sec), humanRate(wbytes/sec)))
            }
            prevDisk[d] = c
        }
        sort.Strings(diskRates)

        // Network rates
        netNow, _ := readNetDev()
        netRates := make([]string, 0)
        for _, ifc := range ifaces {
            cur, ok := netNow[ifc]
            if !ok {
                continue
            }
            if p, ok := prevNet[ifc]; ok {
                rx := float64(cur.rxBytes - p.rxBytes)
                tx := float64(cur.txBytes - p.txBytes)
                sec := interval.Seconds()
                if sec <= 0 {
                    sec = 1
                }
                netRates = append(netRates, fmt.Sprintf("%s: ↓ %s  ↑ %s", ifc, humanRate(rx/sec), humanRate(tx/sec)))
            }
            prevNet[ifc] = cur
        }
        sort.Strings(netRates)

        // Temperatures (best-effort)
        temps, _ := readThermalZones()
        // unique by label (keep first)
        seen := make(map[string]bool)
        tempLines := make([]string, 0)
        for _, t := range temps {
            if t.label == "" {
                continue
            }
            if seen[t.label] {
                continue
            }
            seen[t.label] = true
            tempLines = append(tempLines, fmt.Sprintf("%s: %.1f°C", t.label, t.c))
        }
        sort.Strings(tempLines)

        // Render
        clearScreen()
        fmt.Printf("fnOS 监控  | %s\n", time.Now().Format("2006-01-02 15:04:05"))
        fmt.Println(strings.Repeat("-", 60))
        if cpuErr == nil {
            fmt.Printf("CPU 使用率: %.1f%%\n", cpuUsage)
        } else {
            fmt.Printf("CPU 使用率: N/A (%v)\n", cpuErr)
        }
        if memErr == nil {
            fmt.Printf("内存: %s / %s (%.1f%%)\n", humanBytes(memUsedKB*1024), humanBytes(memTotalKB*1024), memPct)
        } else {
            fmt.Printf("内存: N/A (%v)\n", memErr)
        }
        if dErr == nil {
            fmt.Printf("磁盘空间(%s): 已用 %s  可用 %s  总计 %s\n", *mount, humanBytes(dUsed), humanBytes(dFree), humanBytes(dTotal))
        } else {
            fmt.Printf("磁盘空间(%s): N/A (%v)\n", *mount, dErr)
        }
        if len(diskRates) > 0 {
            fmt.Println("磁盘速率:")
            for _, l := range diskRates {
                fmt.Printf("  %s\n", l)
            }
        } else {
            fmt.Println("磁盘速率: 无数据或不支持")
        }
        if len(netRates) > 0 {
            fmt.Println("网络速率:")
            for _, l := range netRates {
                fmt.Printf("  %s\n", l)
            }
        } else {
            fmt.Println("网络速率: 无数据或不支持")
        }
        if len(tempLines) > 0 {
            fmt.Println("温度:")
            for _, l := range tempLines {
                fmt.Printf("  %s\n", l)
            }
        } else {
            fmt.Println("温度: 未检测到传感器或需要安装 lm-sensors/启用 hwmon")
        }
        fmt.Println(strings.Repeat("-", 60))
        fmt.Printf("提示: 可用 -interval 调整刷新间隔, -mount 选择观察挂载点\n")
    }
}

