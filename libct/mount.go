// +build linux

package libct

import (
	"fmt"
	"syscall"

	_libct "github.com/xemul/libct/go"
	"github.com/docker/libcontainer/devices"
	"github.com/docker/libcontainer/label"
	"github.com/docker/libcontainer/mount"
)

// default mount point flags
const defaultMountFlags = _libct.CT_FS_NOEXEC | _libct.CT_FS_NOSUID | _libct.CT_FS_NODEV

// TODO: this is crappy right now and should be cleaned up with a better way of handling system and
// standard bind mounts allowing them to be more dynamic
func newSystemMounts(mountLabel string, mounts mount.Mounts) []mount_entry {
	systemMounts := []mount_entry{
		{source: "proc", path: "/proc", device: "proc", flags: defaultMountFlags},
		{source: "sysfs", path: "/sys", device: "sysfs", flags: defaultMountFlags},
		{source: "tmpfs", path: "/dev", device: "tmpfs",
			flags: _libct.CT_FS_NOSUID | _libct.CT_FS_STRICTATIME,
			data:  label.FormatMountLabel("mode=755", mountLabel)},
		{source: "tmpfs", path: "/sys/fs/cgroup", device: "tmpfs", flags: defaultMountFlags},
		{source: "shm", path: "/dev/shm", device: "tmpfs",
			flags: defaultMountFlags, data: label.FormatMountLabel("mode=1777,size=65536k", mountLabel)},
		{source: "devpts", path: "/dev/pts", device: "devpts",
			flags: _libct.CT_FS_NOSUID | _libct.CT_FS_NOEXEC,
			data:  label.FormatMountLabel("newinstance,ptmxmode=0666,mode=620,gid=5", mountLabel)},
	}

	return systemMounts
}

func setupBindmounts(ct *_libct.Container, rootfs string, mountConfig *mount.MountConfig) error {
	bindMounts := mountConfig.Mounts

	for _, m := range bindMounts.OfType("bind") {
		var flags int

		if !m.Writable {
			flags |= _libct.CT_FS_RDONLY
		}

		if m.Private {
			flags |= _libct.CT_FS_PRIVATE
		}

		if err := ct.AddBindMount(m.Source, m.Destination, flags); err != nil {
			return err
		}
	}
	return nil
}

// Create the device nodes in the container.
func createDeviceNodes(ct *_libct.Container, rootfs string, nodesToCreate []*devices.Device) error {

	for _, node := range nodesToCreate {
		if err := createDeviceNode(ct, rootfs, node); err != nil {
			return err
		}
	}
	return nil
}

// Creates the device node in the rootfs of the container.
func createDeviceNode(ct *_libct.Container, rootfs string, node *devices.Device) error {
	fileMode := node.FileMode
	switch node.Type {
	case 'c':
		fileMode |= syscall.S_IFCHR
	case 'b':
		fileMode |= syscall.S_IFBLK
	default:
		return fmt.Errorf("%c is not a valid device type for device %s", node.Type, node.Path)
	}

	err := ct.AddDeviceNode(node.Path, int(fileMode), int(node.MajorNumber), int(node.MinorNumber))
	if err != nil {
		return fmt.Errorf("mknod %s %s", node.Path, err)
	}
	return nil
}

type mount_entry struct {
	source string
	path   string
	device string
	flags  int
	data   string
}

// mountSystem sets up linux specific system mounts like sys, proc, shm, and devpts
// inside the mount namespace
func mountSystem(ct *_libct.Container, rootfs string, mountConfig *mount.MountConfig) error {
	for _, m := range newSystemMounts(mountConfig.MountLabel, mountConfig.Mounts) {
		err := ct.AddMount(m.source, m.path, m.flags, m.device, m.data)
		if err != nil {
			return fmt.Errorf("mounting %s into %s %s", m.source, m.path, err)
		}
	}
	return nil
}

func SetupPtmx(ct *_libct.Container, rootfs, consolePath string) error {
	if consolePath == "" {
		return nil
	}

	dest := "/dev/console"

	if err := ct.AddBindMount(consolePath, dest, 0); err != nil {
		return fmt.Errorf("bind %s to %s %s", consolePath, dest, err)
	}
	return nil
}

// InitializeMountNamespace setups up the devices, mount points, and filesystems for use inside a
// new mount namepsace
func InitializeMountNamespace(ct *_libct.Container, rootfs, console string, mountConfig *mount.MountConfig) error {
	var (
		err error
	)

	if err := mountSystem(ct, rootfs, mountConfig); err != nil {
		return fmt.Errorf("mount system %s", err)
	}

	if err = ct.SetRoot(rootfs); err != nil {
		return fmt.Errorf("bind mounts %s", err)
	}

	if err := setupBindmounts(ct, rootfs, mountConfig); err != nil {
		return err
	}
	if err := createDeviceNodes(ct, rootfs, mountConfig.DeviceNodes); err != nil {
		return fmt.Errorf("create device nodes %s", err)
	}

	if err := SetupPtmx(ct, rootfs, console); err != nil {
		return err
	}
	return nil
}
