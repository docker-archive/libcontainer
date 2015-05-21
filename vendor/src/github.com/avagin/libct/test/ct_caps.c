/*
 * Test empty "container" creation
 */
#include <libct.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <linux/capability.h>
#include "test.h"

#define TEST_CAPS 0x1234

extern int capget(cap_user_header_t header, const cap_user_data_t data);
extern int capset(cap_user_header_t header, const cap_user_data_t data);

static int set_ct_alive(void *a)
{
	struct __user_cap_header_struct hdr = {_LINUX_CAPABILITY_VERSION_3, 0};
	struct __user_cap_data_struct data[2];

	memset(&data, 0, sizeof(data));

	if (capget(&hdr, data))
		return -1;

	if (data[0].effective != TEST_CAPS)
		return 1;

	*(int *)a = 1;
	return 0;
}

int main(int argc, char **argv)
{
	int *ct_alive;
	libct_session_t s;
	ct_handler_t ct;
	ct_process_desc_t p;
	ct_process_t pr;

	test_init();

	ct_alive = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	*ct_alive = 0;

	s = libct_session_open_local();
	ct = libct_container_create(s, "test");
	p = libct_process_desc_create(s);
	libct_process_desc_set_caps(p, TEST_CAPS, CAPS_ALLCAPS);
	pr = libct_container_spawn_cb(ct, p, set_ct_alive, ct_alive);
	if (libct_handle_is_err(pr))
		return fail("Unable to execute the init process");
	libct_container_wait(ct);
	libct_container_destroy(ct);
	libct_session_close(s);

	if (!*ct_alive)
		return fail("Container is not alive");
	else
		return pass("Container is alive");
}
