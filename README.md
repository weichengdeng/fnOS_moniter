# fnOS 终端监控 (Go)

一个纯标准库实现的 Linux 终端监控工具，适配基于 Debian 的 NAS（如 fnOS）。无需第三方依赖，即可显示：

- CPU 使用率
- 内存使用率
- 磁盘空间使用情况（默认挂载点 `/`）
- 磁盘读/写速率（基于 `/sys/block/<dev>/stat`，自动发现物理盘）
- 网络上/下行速率（基于 `/proc/net/dev`，自动过滤 lo/虚拟网卡）
- 温度（基于 `/sys/class/thermal` 与 `/sys/class/hwmon`，若系统/硬件未暴露则显示为 N/A）

程序为拉式采样，按固定间隔刷新终端输出。

## 运行要求

- 目标系统：Linux（fnOS/Debian）
- 访问文件：`/proc` 与 `/sys` 只读访问权限（普通用户一般可读）

## 构建与运行

### 1) 在 Windows 上交叉编译到 Linux

安装 Go (1.20+)，在项目根目录执行：

```
set CGO_ENABLED=0
set GOOS=linux
set GOARCH=amd64   
rem 如果是 ARM 设备（例如 aarch64）：
rem set GOARCH=arm64

go build -o fnos-monitor
```

编译完成后将 `fnos-monitor` 上传至 NAS（可用 scp、sftp 或其他方式），给可执行权限并运行：

```
chmod +x fnos-monitor
./fnos-monitor -interval 1s -mount /
```

> 注：若你的 fnOS 是不同架构，请把 `GOARCH` 改成 `arm`/`arm64`/`386` 等相应架构。可在 NAS 上执行 `uname -m` 识别，例如 `x86_64` 对应 `amd64`，`aarch64` 对应 `arm64`。

### 2) 在 Linux 上直接构建

```
go build -o fnos-monitor
./fnos-monitor -interval 1s -mount /
```

## 常用参数

- `-interval` 刷新间隔（默认 1s），例如 `-interval 500ms`、`-interval 2s`
- `-mount`    磁盘空间观察的挂载点（默认 `/`）

## 说明与限制

- CPU：通过 `/proc/stat` 两次采样求差计算使用率。
- 内存：通过 `/proc/meminfo` 的 `MemTotal` 与 `MemAvailable` 估算已用与百分比。
- 磁盘空间：使用 `syscall.Statfs` 读取挂载点空间；默认显示 `/`，可用 `-mount` 指定其他挂载点。
- 磁盘速率：从 `/sys/block/<dev>/stat` 读取「读写扇区数」并结合 `hw_sector_size` 得到字节数，以采样间隔求速率；自动忽略 `loop*`、`ram*`、`zram*`、`dm-*`、`md*`、`sr*` 等非物理盘名。
- 网络速率：从 `/proc/net/dev` 读取 RX/TX 字节计数，按采样间隔求速率；忽略 `lo`、`veth*`、`docker*`、`br-*`、`virbr*`、`vmnet*`、`tailscale*`、`wg*`、`zt*` 等虚拟接口。
- 温度：优先读取 `/sys/class/thermal/thermal_zone*/temp`（单位毫摄氏度），同时尝试 `/sys/class/hwmon/hwmon*/temp*_input`；若硬件/内核未暴露传感器或未加载 `lm-sensors` 相关驱动，则可能显示为空。

## 故障排查

- 终端显示 N/A：通常是该指标文件不存在或权限不足（多发生在容器或精简系统）。可在目标机器检查相应路径，例如 `cat /proc/stat`、`cat /proc/meminfo`、`ls /sys/block`、`cat /proc/net/dev`、`ls /sys/class/thermal`。
- 磁盘/网络速率为 0：请确保程序运行时间足够超过一个采样间隔，或系统确实无 IO 活动。
- 温度不显示：尝试在系统安装/启用 `lm-sensors` 并 `sensors-detect`，或确认 NAS 内核是否暴露 hwmon/thermal 接口。

