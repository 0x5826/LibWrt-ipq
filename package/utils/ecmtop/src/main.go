package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var (
		intervalSec = flag.Float64("i", 1.0, "Sampling interval in seconds (default 1.0)")
		limit       = flag.Int("n", 10, "Number of clients to display (default 10)")
		jsonOutput  = flag.Bool("json", false, "Output single snapshot in JSON format and exit")
		onceOutput  = flag.Bool("once", false, "Output single snapshot in plain text and exit")
		devPath     = flag.String("dev", "/dev/ecm_state", "Path to ecm_state char device")
	)
	flag.Parse()

	if *intervalSec <= 0.1 {
		*intervalSec = 0.1
	}

	collector := NewECMCollector(*devPath)

	// 第一次采样打桩建立基线
	snap, err := collector.Collect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing ECM collector: %v\n", err)
		os.Exit(1)
	}

	// 如果是一次性输出模式，等待一个采样周期后输出
	if *jsonOutput || *onceOutput {
		time.Sleep(time.Duration(*intervalSec * float64(time.Second)))
		snap, err = collector.Collect()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error collecting ECM snapshot: %v\n", err)
			os.Exit(1)
		}

		if *jsonOutput {
			data, err := json.MarshalIndent(snap, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "JSON marshal error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(string(data))
			return
		}

		// 文本单次输出
		fmt.Printf("WAN Down: %s (%s) | Up: %s (%s) | Flows: %d\n",
			FormatSpeed(snap.WAN.DownSpeed), FormatBitrate(snap.WAN.DownSpeed),
			FormatSpeed(snap.WAN.UpSpeed), FormatBitrate(snap.WAN.UpSpeed),
			snap.WAN.ActiveFlows)
		fmt.Println("Top Clients:")
		tui := NewTUIRenderer(*limit)
		tui.SortClients(snap.Clients)
		for i, c := range snap.Clients {
			if i >= *limit {
				break
			}
			fmt.Printf("  #%02d %-15s [%-17s] Down: %s | Up: %s | Conns: %d\n",
				i+1, c.IP, c.MAC, FormatSpeed(c.DownSpeed), FormatSpeed(c.UpSpeed), c.ActiveConns)
		}
		return
	}

	// 交互式 TUI 模式
	cleanupTerm := SetupTerminal()
	defer cleanupTerm()

	// 监听系统信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// 监听键盘按键
	keyChan := make(chan byte, 16)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 && err == nil {
				keyChan <- buf[0]
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	tui := NewTUIRenderer(*limit)
	ticker := time.NewTicker(time.Duration(*intervalSec * float64(time.Second)))
	defer ticker.Stop()

	// 立即绘制第一帧
	tui.Render(snap)

	for {
		select {
		case sig := <-sigChan:
			_ = sig
			return

		case key := <-keyChan:
			switch key {
			case 'q', 'Q', 3: // 3 是 Ctrl+C
				return
			case 's', 'S': // 切换排序
				switch tui.SortBy {
				case SortDownSpeed:
					tui.SortBy = SortUpSpeed
				case SortUpSpeed:
					tui.SortBy = SortTotalDown
				case SortTotalDown:
					tui.SortBy = SortConns
				case SortConns:
					tui.SortBy = SortDownSpeed
				}
				if snap != nil {
					tui.Render(snap)
				}
			case 'r', 'R': // 重置累计
				collector.ResetTotals()
				if snap != nil {
					tui.Render(snap)
				}
			case ' ': // 暂停/继续
				tui.Paused = !tui.Paused
				if snap != nil {
					tui.Render(snap)
				}
			}

		case <-ticker.C:
			if !tui.Paused {
				newSnap, err := collector.Collect()
				if err == nil {
					snap = newSnap
					tui.Render(snap)
				}
			}
		}
	}
}
