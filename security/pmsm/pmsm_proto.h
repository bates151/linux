#ifndef _SECURITY_PMSM_PROTO_H
#define _SECURITY_PMSM_PROTO_H


#define PMSM_PROTO_VERSION 3

#define PROVD_PORT 16152
#define PROVD_PORT_STR "16152"


#include <linux/limits.h>

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <sys/types.h>
#endif

/* Structure referring to an inode on a specific superblock */
struct sb_inode {
	unsigned char sb_uuid[16];
	uint64_t ino;
};


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

	NUM_PROVMSG_TYPES
};

struct provmsg_hdr {
	uint32_t msgtype;
	uint32_t cred_id;
};

struct provmsg_boot {
	struct provmsg_hdr header;
	uint32_t version;
};
struct provmsg_credfork {
	struct provmsg_hdr header;
	uint32_t forked_cred;
};
struct provmsg_credfree {
	struct provmsg_hdr header;
};
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
};
struct provmsg_exec {
	struct provmsg_hdr header;
	struct sb_inode inode;
	uint32_t argv_len;
	uint32_t envp_len;
	char argv_envp[ARG_MAX];
};
struct provmsg_file_p {
	struct provmsg_hdr header;
	struct sb_inode inode;
	int32_t mask;
};
struct provmsg_mmap {
	struct provmsg_hdr header;
	struct sb_inode inode;
	uint64_t prot;
	uint64_t flags;
};
struct provmsg_inode_p {
	struct provmsg_hdr header;
	struct sb_inode inode;
	int32_t mask;
};
struct provmsg_inode_alloc {
	struct provmsg_hdr header;
	struct sb_inode inode;
};
struct provmsg_inode_dealloc {
	struct provmsg_hdr header;
	struct sb_inode inode;
};
struct provmsg_setattr {
	struct provmsg_hdr header;
	struct sb_inode inode;
	uint16_t mode;
	uint32_t uid;
	uint32_t gid;
};
struct provmsg_link {
	struct provmsg_hdr header;
	struct sb_inode inode;
	uint64_t dir;
	uint32_t fname_len;
	char fname[NAME_MAX];
};
struct provmsg_unlink {
	struct provmsg_hdr header;
	struct sb_inode dir;
	uint32_t fname_len;
	char fname[NAME_MAX];
};
struct provmsg_mqsend {
	struct provmsg_hdr header;
	uint32_t msgid;
};
struct provmsg_mqrecv {
	struct provmsg_hdr header;
	uint32_t msgid;
};


#endif
