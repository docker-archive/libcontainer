// +build libct

package libcontainer

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"

	libct "github.com/avagin/libct/go"
	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/cgroups/fs"
)

type libctCgroup interface {
	apply(c *libctContainer) error
	stat(c *libctContainer, stats *cgroups.Stats) error
}

func cgset(c *libctContainer, t int, n string, v int64) error {
	return c.ct.ConfigureController(t, n, strconv.FormatInt(v, 10))
}

func cgget(c *libctContainer, t int, n string) (uint64, error) {
	content, err := c.ct.ReadController(t, n)
	if err != nil {
		return 0, err
	}

	value, err := strconv.ParseUint(content, 10, 64)

	return value, nil
}

func cgsets(c *libctContainer, t int, n string, v string) error {
	return c.ct.ConfigureController(t, n, v)
}

type libctCgroupCpuacct struct {
}

func (cg *libctCgroupCpuacct) stat(c *libctContainer, stats *cgroups.Stats) error {
	totalUsage, err := cgget(c, libct.CTL_CPUACCT, "cpuacct.usage")
	if err != nil {
		return err
	}

	stats.CpuStats.CpuUsage.TotalUsage = totalUsage

	return nil
}

func (cg *libctCgroupCpuacct) apply(c *libctContainer) error {
	return nil
}

type libctCgroupCpu struct {
}

func (cg *libctCgroupCpu) stat(c *libctContainer, stats *cgroups.Stats) error {
	return nil
}

func (cg *libctCgroupCpu) apply(c *libctContainer) error {
	cgroup := c.config.Cgroups

	if cgroup.CpuShares != 0 {
		if err := cgset(c, libct.CTL_CPU, "cpu.shares", cgroup.CpuShares); err != nil {
			return err
		}
	}

	if cgroup.CpuPeriod != 0 {
		if err := cgset(c, libct.CTL_CPU, "cpu.cfs_period_us", cgroup.CpuPeriod); err != nil {
			return err
		}
	}

	if cgroup.CpuQuota != 0 {
		if err := cgset(c, libct.CTL_CPU, "cpu.cfs_quota_us", cgroup.CpuQuota); err != nil {
			return err
		}
	}

	return nil
}

type libctMemory struct {
}

func (cg *libctMemory) stat(c *libctContainer, stats *cgroups.Stats) error {
	var (
		val uint64
		err error
	)

	content, err := c.ct.ReadController(libct.CTL_MEMORY, "memory.stat")
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(bytes.NewBufferString(content))
	for sc.Scan() {
		t, v, err := fs.GetCgroupParamKeyValue(sc.Text())
		if err != nil {
			return fmt.Errorf("failed to parse memory.stat (%q) - %v", sc.Text(), err)
		}
		stats.MemoryStats.Stats[t] = v
	}

	if val, err = cgget(c, libct.CTL_MEMORY, "memory.usage_in_bytes"); err != nil {
		return nil
	}
	stats.MemoryStats.Usage = val
	stats.MemoryStats.Cache = stats.MemoryStats.Stats["cache"]
	if val, err = cgget(c, libct.CTL_MEMORY, "memory.max_usage_in_bytes"); err != nil {
		return nil
	}
	stats.MemoryStats.MaxUsage = val
	if val, err = cgget(c, libct.CTL_MEMORY, "memory.failcnt"); err != nil {
		return nil
	}
	stats.MemoryStats.Failcnt = val

	return nil
}

func (cg *libctMemory) apply(c *libctContainer) error {
	cgroup := c.config.Cgroups

	if cgroup.Memory != 0 {
		if err := cgset(c, libct.CTL_MEMORY,
			"memory.limit_in_bytes", cgroup.Memory); err != nil {
			return err
		}
	}
	if cgroup.MemoryReservation != 0 {
		if err := cgset(c, libct.CTL_MEMORY, "memory.soft_limit_in_bytes",
			cgroup.MemoryReservation); err != nil {
			return err
		}
	}
	// By default, MemorySwap is set to twice the size of Memory.
	if cgroup.MemorySwap == 0 && cgroup.Memory != 0 {
		if err := cgset(c, libct.CTL_MEMORY, "memory.memsw.limit_in_bytes",
			cgroup.Memory*2); err != nil {
			return err
		}
	}
	if cgroup.MemorySwap > 0 {
		if err := cgset(c, libct.CTL_MEMORY, "memory.memsw.limit_in_bytes",
			cgroup.MemorySwap); err != nil {
			return err
		}
	}

	if cgroup.OomKillDisable {
		if err := cgsets(c, libct.CTL_MEMORY, "memory.oom_control", "1"); err != nil {
			return err
		}
	}

	return nil
}

type libctBlkio struct {
}

func (cg *libctBlkio) stat(c *libctContainer, stats *cgroups.Stats) error {
	return nil
}

func (cg *libctBlkio) apply(c *libctContainer) error {
	cgroup := c.config.Cgroups

	if cgroup.BlkioWeight != 0 {
		if err := cgset(c, libct.CTL_BLKIO,
			"blkio.weight", cgroup.BlkioWeight); err != nil {
			return err
		}
	}

	if cgroup.BlkioWeightDevice != "" {
		if err := cgsets(c, libct.CTL_BLKIO,
			"blkio.weight_device", cgroup.BlkioWeightDevice); err != nil {
			return err
		}
	}
	if cgroup.BlkioThrottleReadBpsDevice != "" {
		if err := cgsets(c, libct.CTL_BLKIO,
			"blkio.throttle.read_bps_device", cgroup.BlkioThrottleReadBpsDevice); err != nil {
			return err
		}
	}
	if cgroup.BlkioThrottleWriteBpsDevice != "" {
		if err := cgsets(c, libct.CTL_BLKIO,
			"blkio.throttle.write_bps_device", cgroup.BlkioThrottleWriteBpsDevice); err != nil {
			return err
		}
	}
	if cgroup.BlkioThrottleReadIOpsDevice != "" {
		if err := cgsets(c, libct.CTL_BLKIO,
			"blkio.throttle.read_iops_device", cgroup.BlkioThrottleReadIOpsDevice); err != nil {
			return err
		}
	}
	if cgroup.BlkioThrottleWriteIOpsDevice != "" {
		if err := cgsets(c, libct.CTL_BLKIO,
			"blkio.throttle.write_iops_device", cgroup.BlkioThrottleWriteIOpsDevice); err != nil {
			return err
		}
	}

	return nil
}

var subsystems = map[int]libctCgroup{
	libct.CTL_CPU:     &libctCgroupCpu{},
	libct.CTL_CPUACCT: &libctCgroupCpuacct{},
	libct.CTL_MEMORY:  &libctMemory{},
	libct.CTL_BLKIO:   &libctBlkio{},
	libct.CTL_FREEZER: nil,
	libct.CTL_DEVICES: nil,
}

func (c *libctContainer) setupCgroups() error {
	for ct, cg := range subsystems {
		if err := c.ct.AddController(ct); err != nil {
			return newSystemError(err)
		}
		if cg != nil {
			if err := cg.apply(c); err != nil {
				return newSystemError(err)
			}
		}
	}

	return nil
}

// Stats returns the container's statistics for various cgroup subsystems
func (c *libctContainer) Stats() (*Stats, error) {
	var (
		stats = &Stats{}
	)
	stats.CgroupStats = cgroups.NewStats()

	for _, cg := range subsystems {
		if cg != nil {
			if err := cg.stat(c, stats.CgroupStats); err != nil {
				return nil, newSystemError(err)
			}
		}
	}
	return stats, nil
}
