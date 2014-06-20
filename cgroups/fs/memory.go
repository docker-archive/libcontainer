package fs

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"

	"github.com/docker/libcontainer/cgroups"
)

type memoryGroup struct {
}

func (s *memoryGroup) Set(d *data) error {
	dir, err := d.join("memory")
	// only return an error for memory if it was not specified
	if err != nil && (d.c.Memory != 0 || d.c.MemoryReservation != 0 || d.c.MemorySwap != 0) {
		return err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()

	// Only set values if some config was specified.
	if d.c.Memory != 0 || d.c.MemoryReservation != 0 || d.c.MemorySwap != 0 {
		if d.c.Memory != 0 {
			if err := writeFile(dir, "memory.limit_in_bytes", strconv.FormatInt(d.c.Memory, 10)); err != nil {
				return err
			}
		}
		if d.c.MemoryReservation != 0 {
			if err := writeFile(dir, "memory.soft_limit_in_bytes", strconv.FormatInt(d.c.MemoryReservation, 10)); err != nil {
				return err
			}
		}
		// By default, MemorySwap is set to twice the size of RAM.
		// If you want to omit MemorySwap, set it to `-1'.
		if d.c.MemorySwap != -1 {
			if err := writeFile(dir, "memory.memsw.limit_in_bytes", strconv.FormatInt(d.c.Memory*2, 10)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *memoryGroup) Remove(d *data) error {
	return removePath(d.path("memory"))
}

func (s *memoryGroup) GetStats(d *data, stats *cgroups.Stats) error {
	path, err := d.path("memory")
	if err != nil {
		return err
	}

	return GetMemoryStats(path, stats)
}

func GetMemoryStats(path string, stats *cgroups.Stats) error {
	// Set stats from memory.stat.
	statsFile, err := os.Open(filepath.Join(path, "memory.stat"))
	if err != nil {
		return err
	}
	defer statsFile.Close()

	sc := bufio.NewScanner(statsFile)
	for sc.Scan() {
		t, v, err := getCgroupParamKeyValue(sc.Text())
		if err != nil {
			return err
		}
		stats.MemoryStats.Stats[t] = v
	}

	// Set memory usage and max historical usage.
	value, err := getCgroupParamInt(path, "memory.usage_in_bytes")
	if err != nil {
		return err
	}
	stats.MemoryStats.Usage = value
	value, err = getCgroupParamInt(path, "memory.max_usage_in_bytes")
	if err != nil {
		return err
	}
	stats.MemoryStats.MaxUsage = value
	value, err = getCgroupParamInt(path, "memory.failcnt")
	if err != nil {
		return err
	}
	stats.MemoryStats.Failcnt = value

	return nil
}
