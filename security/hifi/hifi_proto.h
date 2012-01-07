#ifndef _SECURITY_HIFI_PROTO_H
#define _SECURITY_HIFI_PROTO_H


#define HIFI_PROTO_VERSION 5
#define PROVD_PORT 16152


#include <linux/limits.h>

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/types.h>
#endif

/* For portability */
#ifndef __GNUC__
#define __attribute__(x)
#endif

/* Structure referring to an inode on a specific superblock */
struct sb_inode {
	unsigned char sb_uuid[16];
	uint64_t ino;
} __attribute__((packed));


/* Protocol definitions */
enum {
	PROVMSG_BOOT,
	PROVMSG_CREDFORK,
	PROVMSG_CREDFREE,
	PROVMSG_SETID,
	PROVMSG_EXEC,
	PROVMSG_FILE_P,
	PROVMSG_MMAP,
	PROVMSG_INODE_P,
	PROVMSG_INODE_ALLOC,
	PROVMSG_INODE_DEALLOC,
	PROVMSG_SETATTR,
	PROVMSG_LINK,
	PROVMSG_UNLINK,
	PROVMSG_MQSEND,
	PROVMSG_MQRECV,
	PROVMSG_SHMAT,

	NUM_PROVMSG_TYPES
};

struct provmsg_hdr {
	uint32_t msgtype;
	uint32_t cred_id;
} __attribute__((packed));

struct provmsg_boot {
	struct provmsg_hdr header;
	uint32_t version;
} __attribute__((packed));
struct provmsg_credfork {
	struct provmsg_hdr header;
	uint32_t forked_cred;
} __attribute__((packed));
struct provmsg_credfree {
	struct provmsg_hdr header;
} __attribute__((packed));
struct provmsg_setid {
	struct provmsg_hdr header;
	uint32_t uid;
	uint32_t gid;
	uint32_t suid;
	uint32_t sgid;
	uint32_t euid;
	uint32_t egid;
	uint32_t fsuid;
	uint32_t fsgid;
} __attribute__((packed));
struct provmsg_exec {
	struct provmsg_hdr header;
	struct sb_inode inode;
	uint32_t argc;
	uint32_t argv_envp_len;
	/* Variable-length string */
	char argv_envp[0];
} __attribute__((packed));
struct provmsg_file_p {
	struct provmsg_hdr header;
	struct sb_inode inode;
	int32_t mask;
} __attribute__((packed));
struct provmsg_mmap {
	struct provmsg_hdr header;
	struct sb_inode inode;
	uint64_t prot;
	uint64_t flags;
} __attribute__((packed));
struct provmsg_inode_p {
	struct provmsg_hdr header;
	struct sb_inode inode;
	int32_t mask;
} __attribute__((packed));
struct provmsg_inode_alloc {
	struct provmsg_hdr header;
	struct sb_inode inode;
} __attribute__((packed));
struct provmsg_inode_dealloc {
	struct provmsg_hdr header;
	struct sb_inode inode;
} __attribute__((packed));
struct provmsg_setattr {
	struct provmsg_hdr header;
	struct sb_inode inode;
	uint32_t uid;
	uint32_t gid;
	uint16_t mode;
} __attribute__((packed));
struct provmsg_link {
	struct provmsg_hdr header;
	struct sb_inode inode;
	uint64_t dir;
	uint32_t fname_len;
	/* Variable-length string */
	char fname[0];
} __attribute__((packed));
struct provmsg_unlink {
	struct provmsg_hdr header;
	struct sb_inode dir;
	uint32_t fname_len;
	/* Variable-length string */
	char fname[0];
} __attribute__((packed));
struct provmsg_mqsend {
	struct provmsg_hdr header;
	uint32_t msgid;
} __attribute__((packed));
struct provmsg_mqrecv {
	struct provmsg_hdr header;
	uint32_t msgid;
} __attribute__((packed));
struct provmsg_shmat {
	struct provmsg_hdr header;
	uint32_t shmid;
	uint32_t flags;
} __attribute__((packed));


#endif
