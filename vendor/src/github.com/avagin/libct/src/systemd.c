#include "systemd.h"
#include "xmalloc.h"
#include "log.h"

#include <unistd.h>
#include <stdio.h>
#include <dbus/dbus.h>

#include "ct.h"
#include "log.h"
#include "util.h"

DBusConnection *get_connection(DBusBusType type)
{
	DBusError error;
	DBusConnection *conn;

	dbus_error_init(&error);
	conn = dbus_bus_get(type, &error);
	if (dbus_error_is_set (&error)) {
		pr_err("dbus error: %s\n", error.message);
		dbus_error_free (&error);
		return NULL;
	}

	return conn;
}

static DBusMessage *dbus_send_message(DBusConnection *conn, DBusMessage *msg)
{
	DBusMessage *reply;
	DBusError error;

	dbus_error_init(&error);
	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &error);
	if (dbus_error_is_set (&error)) {
		pr_err("dbus error: %s\n", error.message);
		dbus_error_free (&error);
		return NULL;
	}

	dbus_connection_flush(conn);
	return reply;
}

static void set_property(DBusMessageIter *props, const char *key, int type, const void *value)
{
	DBusMessageIter prop, var;
	const char type_str[] = { type, '\0' };

	dbus_message_iter_open_container(props, 'r', NULL, &prop);
	dbus_message_iter_append_basic(&prop, 's', &key);
	dbus_message_iter_open_container(&prop, 'v', type_str, &var);
	dbus_message_iter_append_basic(&var, type, value);
	dbus_message_iter_close_container(&prop, &var);
	dbus_message_iter_close_container(props, &prop);
}

static void set_pid(DBusMessageIter *props, int pid)
{
	DBusMessageIter t, a, v;
	const char *key = "PIDs";
	const char *type_str = "au";
	const dbus_int32_t pids[] = { pid };
	const dbus_int32_t *p = pids;

	dbus_message_iter_open_container(props, DBUS_TYPE_STRUCT, NULL, &t);
	dbus_message_iter_append_basic(&t, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&t, 'v', type_str, &v);
	dbus_message_iter_open_container(&v, 'a', "u", &a);
	dbus_message_iter_append_fixed_array(&a, 'u', &p, 1);
	dbus_message_iter_close_container(&v, &a);
	dbus_message_iter_close_container(&t, &v);

	dbus_message_iter_close_container(props, &t);
}

int systemd_start_unit(struct container *ct, int pid)
{
	static const char *mode = "fail";
	char *slice = "system.slice";
	char unit_name[PATH_MAX], *name = unit_name;
	char desc[1024], *pdesc = desc;
	dbus_bool_t yes = true;

	DBusConnection *conn;
	DBusMessage *msg, *reply;
	DBusMessageIter args, props, aux;

	if (ct->slice)
		slice = ct->slice;
	snprintf(unit_name, sizeof(unit_name), "%s-%s.scope", slice, ct->name);
	snprintf(desc, sizeof(desc), "docker container %s", ct->name);

	msg = dbus_message_new_method_call("org.freedesktop.systemd1",
					   "/org/freedesktop/systemd1",
					   "org.freedesktop.systemd1.Manager",
					   "StartTransientUnit");
	if (!msg) {
		pr_err("can't allocate new method call");
		return -1;
	}

	dbus_message_append_args(msg, 's', &name, 's', &mode, 0);

	dbus_message_iter_init_append(msg, &args);

	dbus_message_iter_open_container(&args, 'a', "(sv)", &props);
	set_property(&props, "Description", 's', &pdesc);
	set_property(&props, "Slice", 's', &slice);

	set_property(&props, "MemoryAccounting", 'b', &yes);
	set_property(&props, "CPUAccounting", 'b', &yes);
	set_property(&props, "BlockIOAccounting", 'b', &yes);

	set_pid(&props, pid);
	dbus_message_iter_close_container(&args, &props);

	dbus_message_iter_open_container(&args, 'a', "(sa(sv))", &aux);
	dbus_message_iter_close_container(&args, &aux);

	conn = get_connection(DBUS_BUS_SYSTEM);
	if (conn == NULL)
		return -1;

	reply = dbus_send_message(conn, msg);
	dbus_message_unref(msg);
	if (reply == NULL)
		return -1;

	dbus_message_unref(reply);

	return 0;
}
