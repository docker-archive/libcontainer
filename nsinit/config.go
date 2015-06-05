package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/docker/docker/pkg/units"
	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/configs"
	"github.com/docker/libcontainer/utils"
)

const defaultMountFlags = syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV

var createFlags = []cli.Flag{
	cli.BoolFlag{Name: "cgroup", Usage: "mount the cgroup data for the container"},
	cli.BoolFlag{Name: "read-only", Usage: "set the container's rootfs as read-only"},
	cli.IntFlag{Name: "cpushares", Usage: "set the cpushares for the container"},
	cli.IntFlag{Name: "parent-death-signal", Usage: "set the signal that will be delivered to the process in case the parent dies"},
	cli.IntFlag{Name: "userns", Usage: "set the user namespace root uid"},
	cli.IntFlag{Name: "veth-mtu", Usage: "veth mtu"},
	cli.StringFlag{Name: "apparmor-profile", Usage: "set the apparmor profile"},
	cli.StringFlag{Name: "cpuset-cpus", Usage: "set the cpuset cpus"},
	cli.StringFlag{Name: "cpuset-mems", Usage: "set the cpuset mems"},
	cli.StringFlag{Name: "hostname", Value: getDefaultID(), Usage: "hostname value for the container"},
	cli.StringFlag{Name: "ipc", Value: "", Usage: "ipc namespace"},
	cli.StringFlag{Name: "memory-limit", Usage: "set the memory limit for the container(32M)"},
	cli.StringFlag{Name: "memory-swap", Usage: "set the memory swap limit for the container(32M)"},
	cli.StringFlag{Name: "mnt", Value: "", Usage: "mount namespace"},
	cli.StringFlag{Name: "mount-label", Usage: "set the mount label"},
	cli.StringFlag{Name: "net", Value: "", Usage: "network namespace"},
	cli.StringFlag{Name: "pid", Value: "", Usage: "pid namespace"},
	cli.StringFlag{Name: "process-label", Usage: "set the process label"},
	cli.StringFlag{Name: "rootfs", Usage: "set the rootfs"},
	cli.StringFlag{Name: "uts", Value: "", Usage: "uts namespace"},
	cli.StringFlag{Name: "veth-address", Usage: "veth ip address"},
	cli.StringFlag{Name: "veth-bridge", Usage: "veth bridge"},
	cli.StringFlag{Name: "veth-gateway", Usage: "veth gateway address"},
	cli.StringSliceFlag{Name: "bind", Value: &cli.StringSlice{}, Usage: "add bind mounts to the container"},
	cli.StringSliceFlag{Name: "sysctl", Value: &cli.StringSlice{}, Usage: "set system properties in the container"},
	cli.StringSliceFlag{Name: "tmpfs", Value: &cli.StringSlice{}, Usage: "add tmpfs mounts to the container"},
}

var configCommand = cli.Command{
	Name:  "config",
	Usage: "generate a standard configuration file for a container",
	Flags: createFlags,
	Action: func(context *cli.Context) {
		template := getTemplate()
		modify(template, context)
		data, err := json.MarshalIndent(template, "", "\t")
		if err != nil {
			fatal(err)
		}
		fmt.Printf("%s", data)
	},
}

func modify(config *configs.Config, context *cli.Context) {
	config.ParentDeathSignal = context.Int("parent-death-signal")
	config.Readonlyfs = context.Bool("read-only")
	config.Cgroups.CpusetCpus = context.String("cpuset-cpus")
	config.Cgroups.CpusetMems = context.String("cpuset-mems")
	config.Cgroups.CpuShares = int64(context.Int("cpushares"))
	if rawMem := context.String("memory-limit"); rawMem != "" {
		memory, err := units.FromHumanSize(rawMem)
		if err != nil {
			logrus.Fatalf("invalid memory-limit %s", rawMem)
		}
		config.Cgroups.Memory = memory
	}
	config.Cgroups.MemorySwap = -1
	if rawSwap := context.String("memory-swap"); rawSwap != "" {
		swap, err := units.FromHumanSize(rawSwap)
		if err != nil {
			logrus.Fatalf("invalid memory-swap %s", rawSwap)
		}
		config.Cgroups.MemorySwap = swap
	}
	config.AppArmorProfile = context.String("apparmor-profile")
	config.ProcessLabel = context.String("process-label")
	config.MountLabel = context.String("mount-label")
	rootfs := context.String("rootfs")
	if rootfs != "" {
		config.Rootfs = rootfs
	}
	userns_uid := context.Int("userns")
	if userns_uid != 0 {
		config.Namespaces.Add(configs.NEWUSER, "")
		config.UidMappings = []configs.IDMap{
			{ContainerID: 0, HostID: userns_uid, Size: 1},
			{ContainerID: 1, HostID: 1, Size: userns_uid - 1},
			{ContainerID: userns_uid + 1, HostID: userns_uid + 1, Size: math.MaxInt32 - userns_uid},
		}
		config.GidMappings = []configs.IDMap{
			{ContainerID: 0, HostID: userns_uid, Size: 1},
			{ContainerID: 1, HostID: 1, Size: userns_uid - 1},
			{ContainerID: userns_uid + 1, HostID: userns_uid + 1, Size: math.MaxInt32 - userns_uid},
		}
		for _, node := range config.Devices {
			node.Uid = uint32(userns_uid)
			node.Gid = uint32(userns_uid)
		}
	}
	config.SystemProperties = make(map[string]string)
	for _, sysProp := range context.StringSlice("sysctl") {
		parts := strings.SplitN(sysProp, "=", 2)
		if len(parts) != 2 {
			logrus.Fatalf("invalid system property %s", sysProp)
		}
		config.SystemProperties[parts[0]] = parts[1]
	}
	for _, rawBind := range context.StringSlice("bind") {
		mount := &configs.Mount{
			Device: "bind",
			Flags:  syscall.MS_BIND | syscall.MS_REC,
		}
		parts := strings.SplitN(rawBind, ":", 3)
		switch len(parts) {
		default:
			logrus.Fatalf("invalid bind mount %s", rawBind)
		case 2:
			mount.Source, mount.Destination = parts[0], parts[1]
		case 3:
			mount.Source, mount.Destination = parts[0], parts[1]
			switch parts[2] {
			case "ro":
				mount.Flags |= syscall.MS_RDONLY
			case "rw":
			default:
				logrus.Fatalf("invalid bind mount mode %s", parts[2])
			}
		}
		config.Mounts = append(config.Mounts, mount)
	}
	for _, tmpfs := range context.StringSlice("tmpfs") {
		config.Mounts = append(config.Mounts, &configs.Mount{
			Device:      "tmpfs",
			Destination: tmpfs,
			Flags:       syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV,
		})
	}
	for flag, value := range map[string]configs.NamespaceType{
		"net": configs.NEWNET,
		"mnt": configs.NEWNS,
		"pid": configs.NEWPID,
		"ipc": configs.NEWIPC,
		"uts": configs.NEWUTS,
	} {
		switch v := context.String(flag); v {
		case "host":
			config.Namespaces.Remove(value)
		case "", "private":
			if !config.Namespaces.Contains(value) {
				config.Namespaces.Add(value, "")
			}
			if flag == "net" {
				config.Networks = []*configs.Network{
					{
						Type:    "loopback",
						Address: "127.0.0.1/0",
						Gateway: "localhost",
					},
				}
			}
			if flag == "uts" {
				config.Hostname = context.String("hostname")
			}
		default:
			config.Namespaces.Remove(value)
			config.Namespaces.Add(value, v)
		}
	}
	if bridge := context.String("veth-bridge"); bridge != "" {
		hostName, err := utils.GenerateRandomName("veth", 7)
		if err != nil {
			logrus.Fatal(err)
		}
		network := &configs.Network{
			Type:              "veth",
			Name:              "eth0",
			Bridge:            bridge,
			Address:           context.String("veth-address"),
			Gateway:           context.String("veth-gateway"),
			Mtu:               context.Int("veth-mtu"),
			HostInterfaceName: hostName,
		}
		config.Networks = append(config.Networks, network)
	}
	if context.Bool("cgroup") {
		config.Mounts = append(config.Mounts, &configs.Mount{
			Destination: "/sys/fs/cgroup",
			Device:      "cgroup",
		})
	}
}

func getTemplate() *configs.Config {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	cgroupRoot, err := cgroups.GetThisCgroupDir("devices")
	if err != nil {
		panic(err)
	}
	return &configs.Config{
		Rootfs:            cwd,
		ParentDeathSignal: int(syscall.SIGKILL),
		Capabilities: []string{
			"AUDIT_WRITE",
			"CHOWN",
			"DAC_OVERRIDE",
			"FOWNER",
			"FSETID",
			"KILL",
			"MKNOD",
			"NET_BIND_SERVICE",
			"NET_RAW",
			"SETFCAP",
			"SETGID",
			"SETPCAP",
			"SETUID",
			"SYS_CHROOT",
		},
		Namespaces: configs.Namespaces([]configs.Namespace{
			{Type: configs.NEWIPC},
			{Type: configs.NEWNET},
			{Type: configs.NEWNS},
			{Type: configs.NEWPID},
			{Type: configs.NEWUTS},
		}),
		Cgroups: &configs.Cgroup{
			Name:            filepath.Base(cwd),
			Parent:          cgroupRoot,
			AllowAllDevices: false,
			AllowedDevices:  configs.DefaultAllowedDevices,
		},
		Devices: configs.DefaultAutoCreatedDevices,
		MaskPaths: []string{
			"/proc/kcore",
		},
		ReadonlyPaths: []string{
			"/proc/sys", "/proc/sysrq-trigger", "/proc/irq", "/proc/bus",
		},
		Mounts: []*configs.Mount{
			{
				Source:      "proc",
				Destination: "/proc",
				Device:      "proc",
				Flags:       defaultMountFlags,
			},
			{
				Source:      "tmpfs",
				Destination: "/dev",
				Device:      "tmpfs",
				Flags:       syscall.MS_NOSUID | syscall.MS_STRICTATIME,
				Data:        "mode=755",
			},
			{
				Source:      "devpts",
				Destination: "/dev/pts",
				Device:      "devpts",
				Flags:       syscall.MS_NOSUID | syscall.MS_NOEXEC,
				Data:        "newinstance,ptmxmode=0666,mode=0620,gid=5",
			},
			{
				Device:      "tmpfs",
				Source:      "shm",
				Destination: "/dev/shm",
				Data:        "mode=1777,size=65536k",
				Flags:       defaultMountFlags,
			},
			{
				Source:      "mqueue",
				Destination: "/dev/mqueue",
				Device:      "mqueue",
				Flags:       defaultMountFlags,
			},
			{
				Source:      "sysfs",
				Destination: "/sys",
				Device:      "sysfs",
				Flags:       defaultMountFlags | syscall.MS_RDONLY,
			},
		},
		Rlimits: []configs.Rlimit{
			{
				Type: syscall.RLIMIT_NOFILE,
				Hard: 1024,
				Soft: 1024,
			},
		},
	}

}
