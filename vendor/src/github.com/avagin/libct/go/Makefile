CGO_LDFLAGS	:= -l:libct.a -l:libnl-route-3.a -l:libnl-3.a -l:libapparmor.a -l:libselinux.a -l:libdbus-1.a -lm
LIBRARY_PATH	:= ../.shipped/libnl/lib/.libs:..
export CGO_LDFLAGS LIBRARY_PATH

test:
	go test -v .
