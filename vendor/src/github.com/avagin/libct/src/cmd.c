#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cmd.h"
#include "xmalloc.h"

void free_cmd(struct libct_cmd *cmd)
{
	struct libct_cmd *next;
	int i;

	while (cmd) {
		next = cmd->next;

		if (cmd->envp) {
			for (i = 0; cmd->envp[i]; i++)
				xfree(cmd->envp[i]);
		}
		for (i = 0; cmd->argv[i]; i++)
			xfree(cmd->argv[i]);

		xfree(cmd->envp);
		xfree(cmd->argv);
		xfree(cmd->dir);
		xfree(cmd->path);

		xfree(cmd);
		cmd = next;
	}
}

int __exec_cmd(struct libct_cmd *cmd)
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		pr_perror("Unable to fork");
		return -1;
	}

	if (pid == 0) {
		if (cmd->dir && chdir(cmd->dir) < 0) {
			pr_perror("Unable to change working directory");
			return 1;
		}
		if (cmd->envp)
			execvpe(cmd->path, cmd->argv, cmd->envp);
		else
			execvp(cmd->path, cmd->argv);
		pr_perror("Unable to exec");
		return 1;
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Unable to wait the %d process", pid);
		return -1;
	}

	if (status != 0) {
		pr_perror("The command returned 0x%x", status);
		return -1;
	}

	return 0;
}

int exec_cmd(struct libct_cmd *cmd)
{
	while (cmd) {
		if (__exec_cmd(cmd))
			return -1;
		cmd = cmd->next;
	}

	return 0;
}

struct libct_cmd *__alloc_cmd(struct libct_cmd *src)
{
	struct libct_cmd *dst;
	int i;

	dst = xzalloc(sizeof(*src));
	if (dst == NULL)
		return NULL;

	if (src->dir) {
		dst->dir = xstrdup(src->dir);
		if (!dst->dir)
			goto err;
	}
	dst->path = xstrdup(src->path);
	if (!dst->path)
		goto err;

	if (src->envp) {
		for (i = 0; ; i++) {
			char **env;

			env = xrealloc(dst->envp, sizeof(char *) * (i + 1));
			if (!env)
				goto err;

			dst->envp = env;
			if (src->envp[i] == NULL) {
				dst->envp[i] = NULL;
				break;
			} else {
				dst->envp[i] = xstrdup(src->envp[i]);
				if (!dst->envp[i])
					goto err;
			}
		}
	}

	for (i = 0; ; i++) {
		char **argv;

		argv = xrealloc(dst->argv, sizeof(char *) * (i + 1));
		if (!argv)
			goto err;

		dst->argv = argv;
		if (src->argv[i] == NULL) {
			dst->argv[i] = NULL;
			break;
		} else {
			dst->argv[i] = xstrdup(src->argv[i]);
			if (!dst->argv[i])
				goto err;
		}
	}

	return dst;
err:
	free_cmd(dst);
	return NULL;
}

struct libct_cmd *alloc_cmd(struct libct_cmd *src)
{
	struct libct_cmd *head = NULL, *prev, *dst;

	while (src) {
		dst = __alloc_cmd(src);
		if (dst == NULL)
			goto err;

		if (head == NULL)
			head = dst;
		else
			prev->next = dst;

		prev = dst;
		src = src->next;
	}

	return head;
err:
	free_cmd(head);
	return NULL;
}
