package utils

import (
	"fmt"
	"runtime"
)

func ReadMem() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// 堆对象累计分配的字节数，随着堆对象的分配而增加，当对象被释放时不会减少
	fmt.Printf("TotalAlloc = %v MiB\n", m.TotalAlloc/1024/1024)
	// 从操作系统获取的总内存字节数，衡量的是 Go 运行时为堆、栈和其他内部数据结构保留的虚拟地址空间
	fmt.Printf("Sys = %v MiB\n", m.Sys/1024/1024)
	// 已分配的堆对象的字节数，包括所有可达对象，以及垃圾回收器尚未释放的不可达对象。会随着堆对象的分配而增加，并随着堆被清扫和不可达对象被释放而减少
	fmt.Printf("HeapAlloc = %v MiB\n", m.HeapAlloc/1024/1024)
	// 从操作系统获取的堆内存字节数，估算了堆曾经拥有的最大大小
	fmt.Printf("HeapSys = %v MiB\n", m.HeapSys/1024/1024)
	fmt.Printf("NumGC = %v\n", m.NumGC)
}
