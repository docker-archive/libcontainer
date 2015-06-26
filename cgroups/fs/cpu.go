// +build linux

package fs

import (
	"bufio"
	"os"
	"path/filepath"

	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/configs"
)

type CpuGroup struct {
}

func (s *CpuGroup) Apply(d *data) error {
	// We always want to join the cpu group, to allow fair cpu scheduling
	// on a container basis
	dir, err := d.join("cpu")
	if err != nil && !cgroups.IsNotFound(err) {
		return err
	}

	if err := s.Set(dir, d.c); err != nil {
		return err
	}

	return nil
}

func (s *CpuGroup) Set(path string, cgroup *configs.Cgroup) error {
	if cgroup.CpuShares != 0 {
		if err := writeFileInt(path, "cpu.shares", cgroup.CpuShares); err != nil {
			return err
		}
	}
	if cgroup.CpuPeriod != 0 {
		if err := writeFileInt(path, "cpu.cfs_period_us", cgroup.CpuPeriod); err != nil {
			return err
		}
	}
	if cgroup.CpuQuota != 0 {
		if err := writeFileInt(path, "cpu.cfs_quota_us", cgroup.CpuQuota); err != nil {
			return err
		}
	}
	if cgroup.CpuRtPeriod != 0 {
		if err := writeFileInt(path, "cpu.rt_period_us", cgroup.CpuRtPeriod); err != nil {
			return err
		}
	}
	if cgroup.CpuRtRuntime != 0 {
		if err := writeFileInt(path, "cpu.rt_runtime_us", cgroup.CpuRtRuntime); err != nil {
			return err
		}
	}

	return nil
}

func (s *CpuGroup) Remove(d *data) error {
	return removePath(d.path("cpu"))
}

func (s *CpuGroup) GetStats(path string, stats *cgroups.Stats) error {
	f, err := os.Open(filepath.Join(path, "cpu.stat"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t, v, err := getCgroupParamKeyValue(sc.Text())
		if err != nil {
			return err
		}
		switch t {
		case "nr_periods":
			stats.CpuStats.ThrottlingData.Periods = v

		case "nr_throttled":
			stats.CpuStats.ThrottlingData.ThrottledPeriods = v

		case "throttled_time":
			stats.CpuStats.ThrottlingData.ThrottledTime = v
		}
	}
	return nil
}
