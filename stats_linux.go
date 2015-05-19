package libcontainer

import "github.com/docker/libcontainer/cgroups"

type Stats struct {
	Interfaces  []*NetworkInterface `json:"interfaces"`
	CgroupStats *cgroups.Stats      `json:"cgroup_stats"`
}
