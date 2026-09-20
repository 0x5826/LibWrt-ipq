package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// RawConn 原始连接统计
type RawConn struct {
	Serial     uint64
	SIP        string
	SNode      string
	DIP        string
	DNode      string
	SPort      int
	DPort      int
	Protocol   int
	IsRouted   int
	FromBytes  uint64
	ToBytes    uint64
	FromPackets uint64
	ToPackets   uint64
}

// ClientStats 客户端聚合统计
type ClientStats struct {
	IP          string  `json:"ip"`
	MAC         string  `json:"mac"`
	DownSpeed   float64 `json:"down_speed_bps"` // bytes/s
	UpSpeed     float64 `json:"up_speed_bps"`   // bytes/s
	TotalDown   uint64  `json:"total_down_bytes"`
	TotalUp     uint64  `json:"total_up_bytes"`
	ActiveConns int     `json:"active_conns"`
}

// WANStats WAN 口总统计
type WANStats struct {
	DownSpeed   float64 `json:"down_speed_bps"` // bytes/s
	UpSpeed     float64 `json:"up_speed_bps"`   // bytes/s
	TotalDown   uint64  `json:"total_down_bytes"`
	TotalUp     uint64  `json:"total_up_bytes"`
	ActiveFlows int     `json:"active_flows"`
}

// Snapshot 一次采集快照
type Snapshot struct {
	Timestamp   time.Time     `json:"timestamp"`
	IntervalSec float64       `json:"interval_sec"`
	WAN         WANStats      `json:"wan"`
	Clients     []ClientStats `json:"clients"`
}

// ECMCollector 采集器
type ECMCollector struct {
	DevicePath string
	MajorPath  string

	// 上一次采集的各连接状态: serial -> RawConn
	prevConns map[uint64]RawConn
	prevTime  time.Time

	// 历史累计增量，用于统计 TotalDown / TotalUp
	clientTotals map[string]*clientTotal
	wanTotalDown uint64
	wanTotalUp   uint64
}

type clientTotal struct {
	MAC       string
	TotalDown uint64
	TotalUp   uint64
}

// NewECMCollector 创建采集器
func NewECMCollector(devPath string) *ECMCollector {
	if devPath == "" {
		devPath = "/dev/ecm_state"
	}
	return &ECMCollector{
		DevicePath:   devPath,
		MajorPath:    "/sys/kernel/debug/ecm/ecm_state/state_dev_major",
		prevConns:    make(map[uint64]RawConn),
		clientTotals: make(map[string]*clientTotal),
	}
}

// EnsureDevice 确保设备文件存在
func (c *ECMCollector) EnsureDevice() error {
	if _, err := os.Stat(c.DevicePath); err == nil {
		return nil
	}

	// 尝试从 sysfs 读取 major
	data, err := os.ReadFile(c.MajorPath)
	if err != nil {
		return fmt.Errorf("read ecm major failed: %w", err)
	}

	majorStr := strings.TrimSpace(string(data))
	major, err := strconv.ParseUint(majorStr, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid major '%s': %w", majorStr, err)
	}

	// 设备号 dev_t
	// S_IFCHR 字符设备，mode 0600
	dev := int((major << 8) | (0 & 0xff) | ((0 & 0xfff00) << 12))
	err = syscall.Mknod(c.DevicePath, syscall.S_IFCHR|0600, dev)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("mknod %s failed: %w", c.DevicePath, err)
	}

	return nil
}

// isPrivateIP 判断是否为局域网私网 IP
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	return false
}

// ReadRawConns 从设备读取原始连接
func (c *ECMCollector) ReadRawConns() (map[uint64]RawConn, error) {
	if err := c.EnsureDevice(); err != nil {
		return nil, err
	}

	f, err := os.Open(c.DevicePath)
	if err != nil {
		return nil, fmt.Errorf("open %s failed: %w", c.DevicePath, err)
	}
	defer f.Close()

	conns := make(map[uint64]RawConn)
	scanner := bufio.NewScanner(f)
	// 适当加大单行缓冲区
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "conns.conn.") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]

		// 格式: conns.conn.<serial>.<field...>
		sub := key[len("conns.conn."):]
		dotIdx := strings.IndexByte(sub, '.')
		if dotIdx <= 0 {
			continue
		}

		serialStr := sub[:dotIdx]
		field := sub[dotIdx+1:]

		serial, err := strconv.ParseUint(serialStr, 10, 64)
		if err != nil {
			continue
		}

		conn := conns[serial]
		conn.Serial = serial

		switch field {
		case "sip_address":
			conn.SIP = val
		case "snode_address":
			conn.SNode = val
		case "dip_address":
			conn.DIP = val
		case "dnode_address":
			conn.DNode = val
		case "sport":
			conn.SPort, _ = strconv.Atoi(val)
		case "dport":
			conn.DPort, _ = strconv.Atoi(val)
		case "protocol":
			conn.Protocol, _ = strconv.Atoi(val)
		case "is_routed":
			conn.IsRouted, _ = strconv.Atoi(val)
		case "adv_stats.from_data_total":
			conn.FromBytes, _ = strconv.ParseUint(val, 10, 64)
		case "adv_stats.to_data_total":
			conn.ToBytes, _ = strconv.ParseUint(val, 10, 64)
		case "adv_stats.from_packet_total":
			conn.FromPackets, _ = strconv.ParseUint(val, 10, 64)
		case "adv_stats.to_packet_total":
			conn.ToPackets, _ = strconv.ParseUint(val, 10, 64)
		}
		conns[serial] = conn
	}

	return conns, scanner.Err()
}

// Collect 一次采样计算差分
func (c *ECMCollector) Collect() (*Snapshot, error) {
	now := time.Now()
	currConns, err := c.ReadRawConns()
	if err != nil {
		return nil, err
	}

	interval := now.Sub(c.prevTime).Seconds()
	if c.prevTime.IsZero() || interval <= 0 {
		interval = 1.0
	}

	// 临时结构用于聚合客户端增量与连接数
	type clientDelta struct {
		mac       string
		deltaDown uint64
		deltaUp   uint64
		conns     int
	}
	clientMap := make(map[string]*clientDelta)

	var wanDeltaDown, wanDeltaUp uint64
	activeFlows := 0

	for serial, curr := range currConns {
		if curr.IsRouted != 1 {
			// 只统计经过 WAN 路由转发的流量
			continue
		}
		activeFlows++

		// 区分局域网客户端 IP/MAC 与外网
		var clientIP, clientMAC string
		var flowDownDelta, flowUpDelta uint64

		prev, exists := c.prevConns[serial]

		if isPrivateIP(curr.SIP) {
			clientIP = curr.SIP
			clientMAC = curr.SNode
			if exists {
				if curr.ToBytes >= prev.ToBytes {
					flowDownDelta = curr.ToBytes - prev.ToBytes
				}
				if curr.FromBytes >= prev.FromBytes {
					flowUpDelta = curr.FromBytes - prev.FromBytes
				}
			}
		} else if isPrivateIP(curr.DIP) {
			clientIP = curr.DIP
			clientMAC = curr.DNode
			if exists {
				if curr.FromBytes >= prev.FromBytes {
					flowDownDelta = curr.FromBytes - prev.FromBytes
				}
				if curr.ToBytes >= prev.ToBytes {
					flowUpDelta = curr.ToBytes - prev.ToBytes
				}
			}
		} else {
			// 两端都不是私网（或特殊隧道），默认按 SIP 处理
			clientIP = curr.SIP
			clientMAC = curr.SNode
			if exists {
				if curr.ToBytes >= prev.ToBytes {
					flowDownDelta = curr.ToBytes - prev.ToBytes
				}
				if curr.FromBytes >= prev.FromBytes {
					flowUpDelta = curr.FromBytes - prev.FromBytes
				}
			}
		}

		wanDeltaDown += flowDownDelta
		wanDeltaUp += flowUpDelta

		cd, ok := clientMap[clientIP]
		if !ok {
			cd = &clientDelta{mac: clientMAC}
			clientMap[clientIP] = cd
		}
		if clientMAC != "" && cd.mac == "" {
			cd.mac = clientMAC
		}
		cd.deltaDown += flowDownDelta
		cd.deltaUp += flowUpDelta
		cd.conns++
	}

	// 累加总计
	c.wanTotalDown += wanDeltaDown
	c.wanTotalUp += wanDeltaUp

	snapshot := &Snapshot{
		Timestamp:   now,
		IntervalSec: interval,
		WAN: WANStats{
			DownSpeed:   float64(wanDeltaDown) / interval,
			UpSpeed:     float64(wanDeltaUp) / interval,
			TotalDown:   c.wanTotalDown,
			TotalUp:     c.wanTotalUp,
			ActiveFlows: activeFlows,
		},
		Clients: make([]ClientStats, 0, len(clientMap)),
	}

	for ip, cd := range clientMap {
		tot, ok := c.clientTotals[ip]
		if !ok {
			tot = &clientTotal{MAC: cd.mac}
			c.clientTotals[ip] = tot
		}
		if cd.mac != "" {
			tot.MAC = cd.mac
		}
		tot.TotalDown += cd.deltaDown
		tot.TotalUp += cd.deltaUp

		snapshot.Clients = append(snapshot.Clients, ClientStats{
			IP:          ip,
			MAC:         tot.MAC,
			DownSpeed:   float64(cd.deltaDown) / interval,
			UpSpeed:     float64(cd.deltaUp) / interval,
			TotalDown:   tot.TotalDown,
			TotalUp:     tot.TotalUp,
			ActiveConns: cd.conns,
		})
	}

	c.prevConns = currConns
	c.prevTime = now

	return snapshot, nil
}

// ResetTotals 重置累计流量
func (c *ECMCollector) ResetTotals() {
	c.clientTotals = make(map[string]*clientTotal)
	c.wanTotalDown = 0
	c.wanTotalUp = 0
}
