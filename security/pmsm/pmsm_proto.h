#ifndef _SECURITY_PMSM_PROTO_H
#define _SECURITY_PMSM_PROTO_H


#define PMSM_PROTO_VERSION 2

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
	ino_t ino;
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
	uid_t uid;
	gid_t gid;
	uid_t suid;
	gid_t sgid;
	uid_t euid;
	gid_t egid;
	uid_t fsuid;
	gid_t fsgid;
};
struct provmsg_exec {
	struct provmsg_hdr header;
	struct sb_inode inode;
	unsigned int argv_envp_len;
	char argv_envp[ARG_MAX];
};
struct provmsg_file_p {
	struct provmsg_hdr header;
	struct sb_inode inode;
	int mask;
};
struct provmsg_mmap {
	struct provmsg_hdr header;
	struct sb_inode inode;
	unsigned long prot;
	unsigned long flags;
};
struct provmsg_inode_p {
	struct provmsg_hdr header;
	struct sb_inode inode;
	int mask;
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
	uid_t uid;
	gid_t gid;
};
struct provmsg_link {
	struct provmsg_hdr header;
	struct sb_inode inode;
	ino_t dir;
	unsigned int fname_len;
	char fname[NAME_MAX];
};
struct provmsg_unlink {
	struct provmsg_hdr header;
	struct sb_inode dir;
	unsigned int fname_len;
	char fname[NAME_MAX];
};
struct provmsg_mqsend {
	struct provmsg_hdr header;
	uint32_t ipcid;
};
struct provmsg_mqrecv {
	struct provmsg_hdr header;
	uint32_t ipcid;
};


#endif
