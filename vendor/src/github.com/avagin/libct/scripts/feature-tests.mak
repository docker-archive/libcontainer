define LIBAPPARMOR_DEV_TEST

#include <sys/apparmor.h>

int main(void)
{
        return 0;
}
endef

define LIBSELINUX_DEV_TEST

#include <selinux/selinux.h>

int main(void)
{
        return 0;
}
endef
