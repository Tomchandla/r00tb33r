#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/stat.h>

#include <ctype.h>
#include <glob.h>
#include <kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kutil.h"

#define MAXITEMS 128

struct item {
	char name[MAXPATHLEN];
	char path[MAXPATHLEN];
	char src[MAXPATHLEN];
};

static struct item items[MAXITEMS];
static int nitems_;

static char *trim(char *s)
{
	char *e;

	while (isspace((unsigned char)*s))
		s++;
	e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = '\0';
	return (s);
}

static void unquote(char *s)
{
	size_t n = strlen(s);

	if (n >= 2 && (s[0] == '"' || s[0] == '\'') && s[n - 1] == s[0]) {
		memmove(s, s + 1, n - 2);
		s[n - 2] = '\0';
	}
}

static void strip_ko(char *s)
{
	size_t n = strlen(s);

	if (n > 3 && strcmp(s + n - 3, ".ko") == 0)
		s[n - 3] = '\0';
}

static struct item *find_item(const char *name)
{
	int i;

	for (i = 0; i < nitems_; i++)
		if (strcmp(items[i].name, name) == 0)
			return (&items[i]);
	return (NULL);
}

static struct item *add_item(const char *name, const char *src)
{
	struct item *it;

	if ((it = find_item(name)) != NULL)
		return (it);
	if (nitems_ >= MAXITEMS)
		return (NULL);
	it = &items[nitems_++];
	memset(it, 0, sizeof(*it));
	strlcpy(it->name, name, sizeof(it->name));
	strlcpy(it->src, src, sizeof(it->src));
	return (it);
}

static void add_token(char *tok, const char *src)
{
	struct item *it;
	char name[MAXPATHLEN];
	const char *base;

	if (*tok == '\0')
		return;
	base = strrchr(tok, '/');
	base = base ? base + 1 : tok;
	strlcpy(name, base, sizeof(name));
	strip_ko(name);
	if (*name == '\0')
		return;
	if ((it = add_item(name, src)) != NULL && strchr(tok, '/') != NULL)
		strlcpy(it->path, tok, sizeof(it->path));
}

static void parse_file(const char *file, int is_loader)
{
	FILE *fp;
	char line[1024];

	if ((fp = fopen(file, "r")) == NULL)
		return;
	while (fgets(line, sizeof(line), fp) != NULL) {
		char *s = trim(line), *eq, *key, *val;

		if (*s == '#' || *s == '\0')
			continue;
		if ((eq = strchr(s, '=')) == NULL)
			continue;
		*eq = '\0';
		key = trim(s);
		val = trim(eq + 1);
		unquote(val);
		val = trim(val);

		if (is_loader) {
			size_t kl = strlen(key);

			if (kl > 5 && strcmp(key + kl - 5, "_load") == 0 &&
			    strcasecmp(val, "YES") == 0) {
				key[kl - 5] = '\0';
				(void)add_item(key, file);
			} else if (kl > 5 && strcmp(key + kl - 5, "_name") == 0) {
				struct item *it;

				key[kl - 5] = '\0';
				if ((it = add_item(key, file)) != NULL)
					strlcpy(it->path, val, sizeof(it->path));
			}
		} else {
			size_t kl = strlen(key);
			char *tok;

			if (kl > 0 && key[kl - 1] == '+')
				key[kl - 1] = '\0';
			if (strcmp(key, "kld_list") != 0)
				continue;
			for (tok = strtok(val, " \t"); tok != NULL;
			    tok = strtok(NULL, " \t"))
				add_token(tok, file);
		}
	}
	fclose(fp);
}

static void parse_glob(const char *pattern, int is_loader)
{
	glob_t g;
	size_t i;

	if (glob(pattern, 0, NULL, &g) != 0)
		return;
	for (i = 0; i < g.gl_pathc; i++)
		parse_file(g.gl_pathv[i], is_loader);
	globfree(&g);
}

static int file_exists(const char *p)
{
	struct stat st;

	return (stat(p, &st) == 0 && S_ISREG(st.st_mode));
}

static int locate(const struct item *it, char *out, size_t len)
{
	if (it->path[0] != '\0') {
		if (file_exists(it->path)) {
			strlcpy(out, it->path, len);
			return (1);
		}
		return (0);
	}
	snprintf(out, len, "/boot/modules/%s.ko", it->name);
	if (file_exists(out))
		return (1);
	snprintf(out, len, "/boot/kernel/%s.ko", it->name);
	return (file_exists(out));
}

static int enumerated(const struct modmap *m, const char *kofile)
{
	int i;

	for (i = 0; i < m->n; i++)
		if (strcmp(m->mods[i].name, kofile) == 0)
			return (1);
	return (0);
}

int check_bootcfg(kvm_t *kd, const struct modmap *m)
{
	char path[MAXPATHLEN], kofile[MAXPATHLEN], full[MAXPATHLEN];
	const char *base;
	int i, findings = 0, found;

	(void)kd;
	nitems_ = 0;
	parse_file("/boot/loader.conf", 1);
	parse_file("/boot/loader.conf.local", 1);
	parse_glob("/boot/loader.conf.d/*", 1);
	parse_file("/etc/rc.conf", 0);
	parse_file("/etc/rc.conf.local", 0);
	parse_glob("/etc/rc.conf.d/*", 0);

	for (i = 0; i < nitems_; i++) {
		struct item *it = &items[i];

		if (!locate(it, path, sizeof(path)))
			continue;
		base = strrchr(path, '/');
		base = base ? base + 1 : path;
		strlcpy(kofile, base, sizeof(kofile));
		if (enumerated(m, kofile))
			continue;

		snprintf(full, sizeof(full), "%s", kofile);
		found = (kldfind(full) > 0) || (modfind(it->name) >= 0);

		if (found) {
			report_hook("'%s' (configured in %s) resolves via "
			    "kldfind/modfind but is missing from the kldstat "
			    "listing: module enumeration is being filtered "
			    "(rootkit)", kofile, it->src);
			findings++;
		} else if (strncmp(path, "/boot/modules/", 14) == 0) {
			report_hook("'%s' is configured to load at boot (%s) and "
			    "present at %s but is not loaded or visible: hidden "
			    "module (rootkit)", it->name, it->src, path);
			findings++;
		} else {
			report_warn("'%s' configured in %s (%s) is not "
			    "loaded", it->name, it->src, path);
		}
	}
	return (findings);
}
