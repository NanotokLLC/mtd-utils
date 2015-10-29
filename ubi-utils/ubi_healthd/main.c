#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <mtd/ubi-user.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <poll.h>
#include <sys/timerfd.h>

#include <getopt.h>
#include <libubi.h>

#include "list.h"

#define log(M, ...) fprintf(stderr, "%s:%d " M "\n", __FILE__, __LINE__,  ##__VA_ARGS__);
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static const char opt_string[] = "d:f:";

/* TODO(sahne):
 * 	- option for defining read delay (number of hours/days until all PEBs should be read)
 * 	- read stats regularily to identify read hotspots and schedule read
 * 	- option for defining scrub delay (number of days/weeks until all PEBs should be scrubbed)
 * 	- log verbosity
 * 	- file to save stats (might be static volume in the future)
 */

/*
 * Basic algorithm:
 *  - get number of PEBs and identify sleep times between scheduling
 *  - read stats to identify hotspots (schedule full block read if identified as such)
 *  - read PEB and remove from list (move to tail ?)
 */

const struct option options[] = {
	{
		.name = "device",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'd'
	},
	{
		.name = "file",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'f'
	},
};

struct peb_info {
	int64_t peb_num;
	uint64_t err_cnt;
	uint64_t read_cnt;
	uint64_t bitflips;
	time_t last_stat_update;
	time_t last_read;
	time_t last_err;
	time_t last_bf;
} __attribute__((packed));

typedef enum {
	SCHED_READ,
	SCHED_SCRUB
} sched_type;

struct sched_peb {
	struct peb_info *peb;
	sched_type type;
	struct list_head list;
};

struct peb_list {
	struct peb_info *peb;
	struct list_head list;
};

/* TODO(sahne): useful default value ? */
char *ubi_dev = "/dev/ubi0";

static int64_t get_num_pebs(const char *ubi_dev)
{
	libubi_t libubi = libubi_open();
	struct ubi_dev_info dev_info;
	int err;
	err = ubi_get_dev_info(libubi, ubi_dev, &dev_info);
	if (err) {
		log("Could not get ubi info for device %s", ubi_dev);
		return -1;
	}
	libubi_close(libubi);
	return dev_info.total_lebs;
}

static int write_stats_file(const char *filename, struct peb_list *peb_head, int64_t next_read_peb, int64_t next_scrub_peb, int pnum)
{
	FILE *file = fopen(filename, "wb");
	if (file == NULL)
		return -1;
	struct peb_info *peb = NULL;
	struct peb_list *p = NULL;
	fwrite(&pnum, sizeof(pnum), 1, file);
	fwrite(&next_read_peb, sizeof(next_read_peb), 1, file);
	fwrite(&next_scrub_peb, sizeof(next_scrub_peb), 1, file);
	list_for_each_entry(p, &peb_head->list, list) {
		peb = p->peb;
		fwrite(peb, sizeof(struct peb_info), 1, file);
	}
	fclose(file);
	return 0;
}

static int read_stats_file(const char *filename, struct peb_list *peb_head, struct sched_peb *sched_read_head, struct sched_peb *sched_scrub_head)
{
	FILE *file = fopen(filename, "rb");
	if (file == NULL)
		return -1;
	struct peb_info *peb = malloc(sizeof(struct peb_info));
	int num_pebs = 0;
	int64_t next_read_peb;
	int64_t next_scrub_peb;
	fread(&num_pebs, sizeof(num_pebs), 1, file);
	fread(&next_read_peb, sizeof(next_read_peb), 1, file);
	fread(&next_scrub_peb, sizeof(next_scrub_peb), 1, file);
	for (ssize_t i = 0; i < num_pebs; i++) {
		struct peb_list *p = NULL;
		fread(peb, sizeof(struct peb_info), 1, file);
		list_for_each_entry(p, &peb_head->list, list) {
			if (p->peb->peb_num == peb->peb_num) {
				free(p->peb);
				p->peb = peb;
			}
		}
	}
	/* rearrange read and scrub scheduling lists */
	struct peb_list *p = NULL;
	struct peb_list *tmp = NULL;
	list_for_each_entry_safe(p, tmp, &sched_read_head->list, list) {
		if (p->peb->peb_num < next_read_peb)
			list_move_tail(&p->list, &sched_read_head->list);
		else
			break;
	}
	p = NULL;
	tmp = NULL;
	list_for_each_entry_safe(p, tmp, &sched_scrub_head->list, list) {
		if (p->peb->peb_num < next_scrub_peb)
			list_move_tail(&p->list, &sched_scrub_head->list);
		else
			break;
	}

	return 0;
}

static int init_stats(int fd, struct list_head *head, int pnum)
{
	int err = 0;
	size_t req_size = pnum * sizeof(struct ubi_stats_entry);
	struct ubi_stats_req *req = malloc(sizeof(struct ubi_stats_req) + req_size);
	if (!req)
		return -1;
	req->req_len = req_size + sizeof(struct ubi_stats_req);
	req->req_pnum = pnum;
	err = ioctl(fd, UBI_IOCSTATS, req);
	if (err < 0) {
		free(req);
		return -1;
	}
	struct peb_info *peb = NULL;
	struct peb_list *p = NULL;
	time_t now = time(NULL);
	for (int i = 0; i < err; i++) {
		struct ubi_stats_entry *s = &req->stats[i];
		peb = malloc(sizeof(struct peb_info));
		peb->peb_num = s->pnum;
		peb->err_cnt = s->ec;
		peb->read_cnt = s->rc;
		peb->bitflips = 0;
		peb->last_stat_update = now;
		p = malloc(sizeof(struct peb_list));
		list_add_tail(&p->list, head);
	}
	return 0;
}

static void free_list(struct peb_list *head)
{
	if (list_empty(&head->list))
		return;
	struct peb_list *p = NULL;
	struct peb_list *tmp = NULL;
	list_for_each_entry_safe(p, tmp, &head->list, list) {
		list_del(&p->list);
		free(p->peb);
		free(p);
	}
}

static int update_stats(int fd, struct peb_list *head, int pnum)
{
	if (list_empty(&head->list)) {
		log("PEB list not initialized");
		return -1;
	}
	int err = 0;
	size_t req_size = pnum * sizeof(struct ubi_stats_entry);
	struct ubi_stats_req *req = malloc(sizeof(struct ubi_stats_req) + req_size);
	if (!req) {
		log("Could not alloc ubi_stats_req: %s", strerror(errno));
		return -1;
	}
	req->req_len = req_size + sizeof(struct ubi_stats_req);
	req->req_pnum = pnum;
	err = ioctl(fd, UBI_IOCSTATS, req);
	if (err) {
		log("Could not get stats for PEBs");
		free(req);
		return -1;
	}
	time_t now = time(NULL);
	for (int i = 0; i < pnum; i++) {
		struct ubi_stats_entry *s = &req->stats[i];
		struct peb_list *p = NULL;
		struct peb_info *peb = NULL;
		list_for_each_entry(p, &head->list, list) {
			if (p->peb->peb_num == s->pnum) {
				peb = p->peb;
				break;
			}
		}
		if (!peb) {
			log("Could not get stats for PEB %d", pnum);
			continue;
		}
		/* TODO(sahne): check for overflow ! */
		peb->err_cnt = s->ec;
		/* XXX(sahne): read count will be reset after erase */
		peb->read_cnt = s->rc;
		peb->last_stat_update = now;
	}
	free(req);
	return 0;
}

static int read_peb(int fd, struct peb_info *peb)
{
	time_t now = time(NULL);
	int err = ioctl(fd, UBI_IOCRPEB, &peb->peb_num);
	if (err < 0) {
		peb->last_bf = now;
		peb->bitflips++;
	}
	peb->last_read = now;
	return 0;
}

static int scrub_peb(int fd, struct peb_info *peb)
{
	time_t now = time(NULL);
	int err = ioctl (fd, UBI_IOCSPEB, &peb->peb_num);
	if (err < 0) {
		peb->last_bf = now;
		peb->bitflips++;
	}
	peb->last_read = now;
	return 0;
}

static int schedule_peb(struct list_head *sched_list, struct peb_info *peb, sched_type type)
{
	struct sched_peb *s = malloc(sizeof(struct sched_peb));
	if (!s)
		return -1;
	s->peb = peb;
	s->type = type;
	list_add_tail(&s->list, sched_list);
	return 0;
}

static int work(struct sched_peb *sched_list, int fd)
{
	if (list_empty(&sched_list->list))
		return 0;
	struct sched_peb *sched = list_first_entry(&sched_list->list, struct sched_peb, list);
	struct peb_info *peb = sched->peb;
	/* delete entry from list, we will add it if needed */
	list_del(&sched->list);
	switch(sched->type) {
	case SCHED_READ:
		read_peb(fd, peb);
		break;
	case SCHED_SCRUB:
		scrub_peb(fd, peb);
		break;
	default:
		log("Unknown work type: %d", sched->type);
		free(sched);
		return -1;
	}
	/* reschedule PEB */
	/* TODO(sahne): check error read/scrub in case PEB went bad (so we don't reschedule it) */
	schedule_peb(&sched_list->list, peb, sched->type);
	free(sched);
	return 1;
}

static int create_and_arm_timer(int seconds)
{
	int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (tfd < 0) {
		log("Could not create timer");
		return -1;
	}
	struct itimerspec tspec = {
		.it_interval = {
			.tv_sec = seconds,
			.tv_nsec = 0,
		},
		.it_value = {
			.tv_sec = 0,
			.tv_nsec = 1,
		},
	};
	if (timerfd_settime(tfd, 0, &tspec, NULL) < 0) {
		log("Could not arm timer");
		close(tfd);
		return -1;
	}

	return tfd;
}

int main(int argc, char **argv)
{
	int c, i;
	int64_t num_pebs;
	struct sched_peb *sched_read_head;
	struct sched_peb *sched_scrub_head;
	struct peb_list *peb_head;
	char *stats_file = "/tmp/ubihealth_stats";

	while ((c = getopt_long(argc, argv, opt_string, options, &i)) != -1) {
		switch(c) {
		case 'd':
			ubi_dev = optarg;
			break;
		case 'f':
			stats_file = optarg;
			break;
		case '?':
		default:
			break;

		}
	}
	/* signal handling */
	int sigfd;
	sigset_t mask;
	struct signalfd_siginfo fdsi;
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGUSR1);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		log("Could not init sigprocmask");
		return 1;
	}
	sigfd = signalfd(-1, &mask, 0);
	if (sigfd < 0) {
		log("Could not init signal handling");
		return 1;
	}

	/* init sched_list */
	peb_head = malloc(sizeof(struct peb_list));
	peb_head->peb = NULL;
	INIT_LIST_HEAD(&peb_head->list);
	sched_read_head = malloc(sizeof(struct sched_peb));
	INIT_LIST_HEAD(&sched_read_head->list);
	sched_read_head->peb = NULL;
	sched_scrub_head = malloc(sizeof(struct sched_peb));
	INIT_LIST_HEAD(&sched_scrub_head->list);
	sched_scrub_head->peb = NULL;
	int fd = open(ubi_dev, O_RDONLY);
	if (fd < 0) {
		log("Could not open device %s", ubi_dev);
		return 1;
	}

	/* get peb info */
	num_pebs = get_num_pebs(ubi_dev);
	if (num_pebs < 1) {
		log("Invalid number of PEBs");
		return 1;
	}
	init_stats(fd, &peb_head->list, num_pebs);
	/* init peb list */

	/* init read and scrub lists */
	struct peb_list *p = NULL;
	struct peb_info *peb = NULL;
	list_for_each_entry(p, &peb_head->list, list) {
		schedule_peb(&sched_read_head->list, peb, SCHED_READ);
		schedule_peb(&sched_scrub_head->list, peb, SCHED_SCRUB);
	}

	if (read_stats_file(stats_file, peb_head, sched_read_head, sched_scrub_head) < 0)
		log("Could not init stats from file %s", stats_file);

	int shutdown = 0;
	int stats_timer = create_and_arm_timer(10);
	int read_peb_timer = create_and_arm_timer(100000 / num_pebs);
	int scrub_peb_timer = create_and_arm_timer(100000000 / num_pebs);
	struct pollfd pfd[4];
	pfd[0].fd = sigfd;
	pfd[0].events = POLLIN;
	pfd[1].fd = stats_timer;
	pfd[1].events = POLLIN;
	pfd[2].fd = read_peb_timer;
	pfd[2].events = POLLIN;
	pfd[3].fd = scrub_peb_timer;
	pfd[3].events = POLLIN;
	while (!shutdown) {
		int n = poll(pfd, ARRAY_SIZE(pfd), -1);
		if (n == -1) {
			log("poll error: %s", strerror(errno));
			shutdown = 1;
		}
		if (n == 0) {
			continue;
		}
		/* signalfd */
		if (pfd[0].revents & POLLIN) {
			ssize_t s = read(sigfd, &fdsi, sizeof(fdsi));
			if (s != sizeof(fdsi)) {
				log("Could not read from signal fd");
				continue;
			}
			switch(fdsi.ssi_signo) {
			case SIGUSR1: {
				/* write back stats to disk */
				int64_t next_read_peb, next_scrub_peb;
				struct sched_peb *p = list_first_entry(&sched_read_head->list, struct sched_peb, list);
				next_read_peb = p->peb->peb_num;
				p = list_first_entry(&sched_scrub_head->list, struct sched_peb, list);
				next_scrub_peb = p->peb->peb_num;
				write_stats_file(stats_file, peb_head, next_read_peb, next_scrub_peb, num_pebs);
				break;
				}
			default:
				shutdown = 1;
				break;
			}
		}
		/* stats timer */
		if (pfd[1].revents & POLLIN) {
			/* update stats */
			update_stats(fd, peb_head, num_pebs);
			/* XXX(sahne): POLICY !!!! */
			struct peb_list *p = NULL;
			time_t now = time(NULL);
			/* check if we need to act on any block */
			list_for_each_entry(p, &peb_head->list, list) {
				struct peb_info *peb = p->peb;
				if (difftime(peb->last_read, now) > 3600) {
					schedule_peb(&sched_read_head->list, peb, SCHED_READ);
				}
			}
		}

		/* read_peb_timer */
		if (pfd[2].revents & POLLIN) {
			/* do next peb read */
			if (work(sched_read_head, fd) < 0) {
				log("Error while reading PEB");
			}
		}

		/* scrub pebs */
		if (pfd[3].revents & POLLIN) {
			/* do next peb scrub */
			if (work(sched_scrub_head, fd) < 0) {
				log("Error while scrubbing PEB");
			}
		}

	}
	close(fd);
	free_list(peb_head);

	return 0;
}
