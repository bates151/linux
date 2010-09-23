#ifndef _SECURITY_PMSM_H
#define _SECURITY_PMSM_H


#include <linux/types.h>
#include <linux/xattr.h>


/* Key names for xattrs */
#define XATTR_PMSM_SUFFIX "pmsm"
#define XATTR_NAME_PMSM XATTR_SECURITY_PREFIX XATTR_PMSM_SUFFIX


/* Shortcut for security_operations */
#define HANDLE(HOOK) .HOOK = pmsm_##HOOK



/*
 * Security label for struct cred.  The 32-bit ID is just an incremental number
 * which, for a proof-of-concept implementation, should do enough to avoid
 * collisions.  This ought to be implemented later in a similar fashion to PID
 * numbering (bit array?).
 */
struct cred_security {
	u32 csid;
	int exempt;
};


/*
 * Security label for filesystems via struct super_block.  This UUID is stored
 * in the xattr of the root inode for persistence.  If we encounter a filesystem
 * with no such label, we create one and store it ourselves.
 */
struct sb_security {
	unsigned char uuid[16];
};


/* Security structure for inodes. */
struct inode_security {
	int is_new;
};

/* Security structure for XSI message queues */
struct msg_security {
	u32 msgid;
};


#endif
