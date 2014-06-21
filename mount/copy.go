// +build linux

package mount

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/dotcloud/docker/pkg/system"
)

func copyRegular(srcPath, dstPath string, mode os.FileMode) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)

	return err
}

func copyXattr(srcPath, dstPath, attr string) error {
	data, err := system.Lgetxattr(srcPath, attr)
	if err != nil {
		return err
	}
	if data != nil {
		if err := system.Lsetxattr(dstPath, attr, data, 0); err != nil {
			return err
		}
	}
	return nil
}

func copyDir(srcDir, dstDir string) error {
	err := filepath.Walk(srcDir, func(srcPath string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Rebase path
		relPath, err := filepath.Rel(srcDir, srcPath)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dstDir, relPath)
		if err != nil {
			return err
		}

		stat, ok := f.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("Unable to get raw syscall.Stat_t data for %s", srcPath)
		}

		switch f.Mode() & os.ModeType {
		case 0: // Regular file
			if err := copyRegular(srcPath, dstPath, f.Mode()); err != nil {
				return err
			}

		case os.ModeDir:
			if err := os.Mkdir(dstPath, f.Mode()); err != nil && !os.IsExist(err) {
				return err
			}

		case os.ModeSymlink:
			link, err := os.Readlink(srcPath)
			if err != nil {
				return err
			}

			if err := os.Symlink(link, dstPath); err != nil {
				return err
			}

		case os.ModeNamedPipe:
			fallthrough
		case os.ModeSocket:
			if err := syscall.Mkfifo(dstPath, stat.Mode); err != nil {
				return err
			}

		case os.ModeDevice:
			if err := syscall.Mknod(dstPath, stat.Mode, int(stat.Rdev)); err != nil {
				return err
			}

		default:
			return fmt.Errorf("Unknown file type for %s\n", srcPath)
		}

		if err := os.Lchown(dstPath, int(stat.Uid), int(stat.Gid)); err != nil {
			return err
		}

		if err := copyXattr(srcPath, dstPath, "trusted.overlay.whiteout"); err != nil {
			return err
		}

		isSymlink := f.Mode()&os.ModeSymlink != 0

		// There is no LChmod, so ignore mode for symlink. Also, this
		// must happen after chown, as that can modify the file mode
		if !isSymlink {
			if err := os.Chmod(dstPath, f.Mode()); err != nil {
				return err
			}
		}

		ts := []syscall.Timespec{stat.Atim, stat.Mtim}
		// syscall.UtimesNano doesn't support a NOFOLLOW flag atm
		if !isSymlink {
			if err := system.UtimesNano(dstPath, ts); err != nil {
				return err
			}
		} else {
			if err := system.LUtimesNano(dstPath, ts); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}
