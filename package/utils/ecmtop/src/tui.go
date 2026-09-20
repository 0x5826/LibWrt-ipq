package main

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// ANSI 转义码
const (
	ColorReset   = "\033[0m"
	ColorBold    = "\033[1m"
	ColorDim     = "\033[2m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"

	ClearScreen = "\033[H\033[2J"
	CursorHome  = "\033[H"
	HideCursor  = "\033[?25l"
	ShowCursor  = "\033[?25h"
)

// SortField 排序字段
type SortField string

const (
	SortDownSpeed SortField = "down"
	SortUpSpeed   SortField = "up"
	SortTotalDown SortField = "total_down"
	SortConns     SortField = "conns"
)

// FormatBytes 格式化字节数 (严格定宽 11 字符右对齐)
func FormatBytes(b uint64) string {
	const unit = 1024
	var raw string
	if b < unit {
		raw = fmt.Sprintf("%d B", b)
	} else {
		div, exp := int64(unit), 0
		for n := b / unit; n >= unit; n /= unit {
			div *= unit
			exp++
		}
		raw = fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
	}
	return fmt.Sprintf("%11s", raw)
}

// FormatSpeed 格式化速率 (严格定宽 12 字符右对齐，绝不漂移)
func FormatSpeed(speed float64) string {
	var raw string
	if speed < 1024 {
		raw = fmt.Sprintf("%.1f B/s", speed)
	} else if speed < 1024*1024 {
		raw = fmt.Sprintf("%.1f KB/s", speed/1024)
	} else if speed < 1024*1024*1024 {
		raw = fmt.Sprintf("%.2f MB/s", speed/(1024*1024))
	} else {
		raw = fmt.Sprintf("%.2f GB/s", speed/(1024*1024*1024))
	}
	return fmt.Sprintf("%12s", raw)
}

// FormatBitrate 格式化比特率 (严格定宽 12 字符右对齐)
func FormatBitrate(speed float64) string {
	bps := speed * 8
	var raw string
	if bps < 1000 {
		raw = fmt.Sprintf("%.0f bps", bps)
	} else if bps < 1000*1000 {
		raw = fmt.Sprintf("%.1f Kbps", bps/1000)
	} else if bps < 1000*1000*1000 {
		raw = fmt.Sprintf("%.2f Mbps", bps/(1000*1000))
	} else {
		raw = fmt.Sprintf("%.2f Gbps", bps/(1000*1000*1000))
	}
	return fmt.Sprintf("%12s", raw)
}

// RenderProgressBar 渲染纯 ASCII 进度条
func RenderProgressBar(ratio float64, width int, filledColor, emptyColor string) string {
	if width <= 0 {
		return ""
	}
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}

	filledLen := int(math.Round(ratio * float64(width)))
	if filledLen > width {
		filledLen = width
	}
	emptyLen := width - filledLen

	return filledColor + strings.Repeat("#", filledLen) + emptyColor + strings.Repeat(".", emptyLen) + ColorReset
}

// TUIRenderer 渲染器
type TUIRenderer struct {
	SortBy SortField
	Limit  int
	Paused bool
}

// NewTUIRenderer 创建渲染器
func NewTUIRenderer(limit int) *TUIRenderer {
	if limit <= 0 {
		limit = 12
	}
	return &TUIRenderer{
		SortBy: SortDownSpeed,
		Limit:  limit,
	}
}

// SortClients 对客户端排序
func (t *TUIRenderer) SortClients(clients []ClientStats) {
	sort.Slice(clients, func(i, j int) bool {
		switch t.SortBy {
		case SortUpSpeed:
			return clients[i].UpSpeed > clients[j].UpSpeed
		case SortTotalDown:
			return clients[i].TotalDown > clients[j].TotalDown
		case SortConns:
			return clients[i].ActiveConns > clients[j].ActiveConns
		case SortDownSpeed:
			fallthrough
		default:
			return clients[i].DownSpeed > clients[j].DownSpeed
		}
	})
}

// Render 绘制一屏 TUI 界面（100 列宽屏，刚性锁死无错位）
func (t *TUIRenderer) Render(snap *Snapshot) {
	t.SortClients(snap.Clients)

	const lineWidth = 100
	divDouble := ColorCyan + strings.Repeat("=", lineWidth) + ColorReset
	divSingle := ColorCyan + strings.Repeat("-", lineWidth) + ColorReset

	var sb strings.Builder
	sb.WriteString(CursorHome)

	pauseTag := ""
	if t.Paused {
		pauseTag = " " + ColorYellow + "[PAUSED]" + ColorReset
	}

	sortName := "Down Speed [DESC]"
	switch t.SortBy {
	case SortUpSpeed:
		sortName = "Up Speed [DESC]"
	case SortTotalDown:
		sortName = "Total Down [DESC]"
	case SortConns:
		sortName = "Active Conns [DESC]"
	}

	// 1. 顶部 Header
	sb.WriteString(divDouble + "\n")
	titleLeft := "LibWrt NSS Hardware Traffic Monitor (ecmtop)"
	titleRight := fmt.Sprintf("[Interval: %.1fs]%s", snap.IntervalSec, pauseTag)
	remSpaces := lineWidth - len(titleLeft) - len(titleRight) - 2
	if remSpaces < 0 {
		remSpaces = 2
	}
	sb.WriteString(fmt.Sprintf(" %s%s%s%s%s\n",
		ColorBold+ColorWhite, titleLeft, ColorReset,
		strings.Repeat(" ", remSpaces), titleRight))
	sb.WriteString(divDouble + "\n\n")

	// 2. WAN 状态区 (物理坐标锁定)
	sb.WriteString(fmt.Sprintf(" %sWAN Status (NSS Hardware Offloaded)%s\n", ColorBold+ColorYellow, ColorReset))

	// WAN Down 进度条 (30 字符纯 ASCII)
	wanDownMbps := (snap.WAN.DownSpeed * 8) / (1000 * 1000)
	wanDownRatio := wanDownMbps / 1000.0
	if wanDownRatio > 1.0 {
		wanDownRatio = 1.0
	}
	barDown := RenderProgressBar(wanDownRatio, 30, ColorGreen, ColorDim)
	sb.WriteString(fmt.Sprintf("   %sRX (Down):%s  %s  (%s)   [%s]  %5.1f%%\n",
		ColorBold+ColorGreen, ColorReset,
		FormatSpeed(snap.WAN.DownSpeed), FormatBitrate(snap.WAN.DownSpeed),
		barDown, wanDownRatio*100))

	// WAN Up 进度条
	wanUpMbps := (snap.WAN.UpSpeed * 8) / (1000 * 1000)
	wanUpRatio := wanUpMbps / 100.0
	if wanUpRatio > 1.0 {
		wanUpRatio = 1.0
	}
	barUp := RenderProgressBar(wanUpRatio, 30, ColorCyan, ColorDim)
	sb.WriteString(fmt.Sprintf("   %sTX (Up):  %s  %s  (%s)   [%s]  %5.1f%%\n\n",
		ColorBold+ColorCyan, ColorReset,
		FormatSpeed(snap.WAN.UpSpeed), FormatBitrate(snap.WAN.UpSpeed),
		barUp, wanUpRatio*100))

	sb.WriteString(fmt.Sprintf("   Total RX: %s   |   Total TX: %s   |   NSS Active Flows: %-5d\n",
		FormatBytes(snap.WAN.TotalDown), FormatBytes(snap.WAN.TotalUp), snap.WAN.ActiveFlows))
	sb.WriteString(divSingle + "\n")

	// 3. 客户端实时排行列表 (100 列从容对齐)
	sb.WriteString(fmt.Sprintf(" %sClient Real-Time Traffic Ranking%s (Sorted by: %s%s%s)\n\n",
		ColorBold+ColorWhite, ColorReset, ColorYellow, sortName, ColorReset))

	// 刚性表头: No(3) + IP(15) + MAC(17) + Down(12) + Up(12) + TotalDown(11) + Conns(7) + Ratio(6) = 85 + 间隙 = 99
	sb.WriteString(fmt.Sprintf("   %s%-3s  %-15s  %-17s  %12s  %12s  %11s  %7s  %6s%s\n",
		ColorBold, "No.", "Client IP", "MAC Address", "Down Speed", "Up Speed", "Total Down", "Conns", "Ratio", ColorReset))
	sb.WriteString(fmt.Sprintf("   %s  %s  %s  %s  %s  %s  %s  %s\n",
		strings.Repeat("-", 3), strings.Repeat("-", 15), strings.Repeat("-", 17),
		strings.Repeat("-", 12), strings.Repeat("-", 12), strings.Repeat("-", 11),
		strings.Repeat("-", 7), strings.Repeat("-", 6)))

	count := len(snap.Clients)
	if count > t.Limit {
		count = t.Limit
	}

	for i := 0; i < count; i++ {
		c := snap.Clients[i]
		mac := c.MAC
		if mac == "" {
			mac = "N/A"
		}

		ratio := 0.0
		if snap.WAN.DownSpeed > 0 {
			ratio = (c.DownSpeed / snap.WAN.DownSpeed) * 100
		}
		if ratio > 100 {
			ratio = 100.0
		}
		ratioStr := fmt.Sprintf("%5.1f%%", ratio)

		// 每一列均强制匹配表头定宽，绝不产生一丁点横向偏移
		sb.WriteString(fmt.Sprintf("   %02d   %-15s  %-17s  %s%s%s  %s%s%s  %s  %7d  %6s\n",
			i+1, c.IP, mac,
			ColorGreen, FormatSpeed(c.DownSpeed), ColorReset,
			ColorCyan, FormatSpeed(c.UpSpeed), ColorReset,
			FormatBytes(c.TotalDown),
			c.ActiveConns, ratioStr))
	}

	// 补齐剩余空行保持画面平稳
	for i := count; i < t.Limit; i++ {
		sb.WriteString(strings.Repeat(" ", lineWidth) + "\n")
	}

	// 4. 底部状态与按键提示
	sb.WriteString(divSingle + "\n")
	sb.WriteString(fmt.Sprintf("   %s[q]%s Quit  |  %s[s]%s Sort (Down/Up/Total/Conns)  |  %s[r]%s Reset  |  %s[Space]%s Pause\n",
		ColorBold+ColorRed, ColorReset,
		ColorBold+ColorYellow, ColorReset,
		ColorBold+ColorMagenta, ColorReset,
		ColorBold+ColorGreen, ColorReset))
	sb.WriteString(divDouble + "\n")

	os.Stdout.WriteString(sb.String())
}

// SetupTerminal 设置终端为原始非阻塞模式
func SetupTerminal() func() {
	cmd := exec.Command("stty", "-F", "/dev/tty", "cbreak", "-echo", "min", "0", "time", "1")
	_ = cmd.Run()
	os.Stdout.WriteString(HideCursor + ClearScreen)

	return func() {
		cmdRestore := exec.Command("stty", "-F", "/dev/tty", "-cbreak", "echo")
		_ = cmdRestore.Run()
		os.Stdout.WriteString(ShowCursor + "\n")
	}
}
