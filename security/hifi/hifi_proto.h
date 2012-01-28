#ifndef _SECURITY_HIFI_PROTO_H
#define _SECURITY_HIFI_PROTO_H


#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/uuid.h>
#else
#include <stdint.h>
#include <sys/types.h>
typedef struct {
	uint8_t b[16];
} uuid_be;
#endif

/* For portability */
#ifndef __GNUC__
#define __attribute__(x)
#endif

/* Structure referring to an inode on a specific superblock */
struct sb_inode {
	uuid_be sb_uuid;
	uint64_t ino;
} __attribute__((packed));

/* Structures referring to a receive queue on a specific system */
struct sockid {
	uint32_t low;
	uint16_t high;
} __attribute__((packed));

struct host_sockid {
	struct sockid sock;
	uuid_be host;
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
	PROVMSG_READLINK,
	PROVMSG_SOCKSEND,
	PROVMSG_SOCKRECV,
	PROVMSG_SOCKALIAS,

	NUM_PROVMSG_TYPES
};

struct provmsg {
	uint16_t len_lo;
#define MSGLEN_LO(n) (n & ((1 << 16) - 1))
	uint8_t len_hi;
#define MSGLEN_HI(n) ((n >> 16) & ((1 << 8) - 1))
	uint8_t type;
	uint32_t cred_id;
} __attribute__((packed));

static inline void msg_initlen(struct provmsg *msg, int len)
{
	msg->len_lo = MSGLEN_LO(len);
	msg->len_hi = MSGLEN_HI(len);
}

static inline int msg_getlen(struct provmsg *msg)
{
	return msg->len_hi << 16 | msg->len_lo;
}

struct provmsg_boot {
	struct provmsg msg;
	uuid_be uuid;
} __attribute__((packed));
struct provmsg_credfork {
	struct provmsg msg;
	uint32_t forked_cred;
} __attribute__((packed));
struct provmsg_credfree {
	struct provmsg msg;
} __attribute__((packed));
struct provmsg_setid {
	struct provmsg msg;
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
	struct provmsg msg;
	struct sb_inode inode;
	uint32_t argc;
	/* Variable-length string */
	char argv_envp[0];
} __attribute__((packed));
struct provmsg_file_p {
	struct provmsg msg;
	struct sb_inode inode;
	int32_t mask;
} __attribute__((packed));
struct provmsg_mmap {
	struct provmsg msg;
	struct sb_inode inode;
	uint64_t prot;
	uint64_t flags;
} __attribute__((packed));
struct provmsg_inode_p {
	struct provmsg msg;
	struct sb_inode inode;
	int32_t mask;
} __attribute__((packed));
struct provmsg_inode_alloc {
	struct provmsg msg;
	struct sb_inode inode;
} __attribute__((packed));
struct provmsg_inode_dealloc {
	struct provmsg msg;
	struct sb_inode inode;
} __attribute__((packed));
struct provmsg_setattr {
	struct provmsg msg;
	struct sb_inode inode;
	uint32_t uid;
	uint32_t gid;
	uint16_t mode;
} __attribute__((packed));
struct provmsg_link {
	struct provmsg msg;
	struct sb_inode inode;
	uint64_t dir;
	/* Variable-length string */
	char fname[0];
} __attribute__((packed));
struct provmsg_unlink {
	struct provmsg msg;
	struct sb_inode dir;
	/* Variable-length string */
	char fname[0];
} __attribute__((packed));
struct provmsg_mqsend {
	struct provmsg msg;
	uint32_t msgid;
} __attribute__((packed));
struct provmsg_mqrecv {
	struct provmsg msg;
	uint32_t msgid;
} __attribute__((packed));
struct provmsg_shmat {
	struct provmsg msg;
	uint32_t shmid;
	uint32_t flags;
} __attribute__((packed));
struct provmsg_readlink {
	struct provmsg msg;
	struct sb_inode inode;
} __attribute__((packed));
struct provmsg_socksend {
	struct provmsg msg;
	struct sockid peer;
} __attribute__((packed));
struct provmsg_sockrecv {
	struct provmsg msg;
	struct host_sockid sock;
} __attribute__((packed));
struct provmsg_sockalias {
	struct provmsg msg;
	struct host_sockid sock;
	struct host_sockid alias;
} __attribute__((packed));

#endif
