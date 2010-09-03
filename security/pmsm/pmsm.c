/*
 *  PM/SM
 *
 *  Monitors provenance at the LSM layer.
 *
 *  TODO:
 *   - Convert the csid management system to something more PID-like (e.g.
 *     used/free bit array).
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include <linux/kmod.h>

#include <linux/highmem.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>

#include <linux/stddef.h>
#include <linux/limits.h>
#include <linux/binfmts.h>
#include <linux/cred.h>

#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/xattr.h>

/* for generate_random_uuid */
#include <linux/random.h>

/* for relay support */
#include <linux/debugfs.h>
#include <linux/relay.h>
#include <linux/spinlock.h>
#include <asm/spinlock.h>

#include "pmsm.h"
#include "pmsm_proto.h"


MODULE_AUTHOR("Devin J. Pohly");
MODULE_LICENSE("GPL");


static atomic_t csid_current = ATOMIC_INIT(0);
static atomic_t ipc_current = ATOMIC_INIT(0);

#define BOOT_BUFFER_SIZE (1 << 10)
static char *boot_buffer;
static unsigned boot_bytes = 0;
#define RELAY_TOTAL_SIZE (32 << 20)
#define NUM_RELAYS 32
static struct rchan *relay;
static DEFINE_SPINLOCK(relay_lock);


/*
 * Relay-related handlers and structures
 */
static struct dentry *relay_create_file(const char *filename,
		struct dentry *parent, int mode, struct rchan_buf *buf,
		int *is_global)
{
	*is_global = 1;
	return debugfs_create_file(filename, mode, parent, buf,
			&relay_file_operations);
}

static int relay_remove_file(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}

static struct rchan_callbacks relay_callbacks = {
	.create_buf_file = relay_create_file,
	.remove_buf_file = relay_remove_file
};

/* Writes to the relay */
static void write_to_relay(const void *data, size_t length)
{
	unsigned long flags;
	spin_lock_irqsave(&relay_lock, flags);
	if (unlikely(!relay)) {
		if (boot_bytes + length > BOOT_BUFFER_SIZE)
			panic("PM/SM: Boot buffer overrun");
		memcpy(boot_buffer + boot_bytes, data, length);
		boot_bytes += length;
	} else {
		relay_write(relay, data, length);
	}
	spin_unlock_irqrestore(&relay_lock, flags);
}

/* Initial message */
static const struct provmsg_boot init_bootmsg = {
	.header.msgtype = PROVMSG_BOOT,
	.header.cred_id = 1,
	.version = PMSM_PROTO_VERSION,
};
static const struct provmsg_setid init_setidmsg = {
	.header.msgtype = PROVMSG_SETID,
	.header.cred_id = 1,
	/* Static, so all IDs are 0 */
};

/* Sets up the relay */
static void init_relay(void)
{
	relay = relay_open("provenance", NULL, (RELAY_TOTAL_SIZE / NUM_RELAYS),
			NUM_RELAYS, &relay_callbacks, NULL);
	if (!relay)
		panic("PM/SM could not create relay");
	write_to_relay(&init_bootmsg, sizeof(init_bootmsg));
	write_to_relay(&init_setidmsg, sizeof(init_setidmsg));
	printk(KERN_INFO "PM/SM: Replaying boot buffer: %uB\n", boot_bytes);
	write_to_relay(boot_buffer, boot_bytes);
	kfree(boot_buffer);
}


/*
 * Function for grabbing the argv from a bprm
 */
static int copy_strings_bprm(struct linux_binprm *bprm, char *dst)
{
	int rv = 0;
	unsigned int count;
	unsigned long src;
	struct page *page, *new_page;
	const char *kaddr;
	unsigned int ofs, remaining, bytes;

	count = bprm->argc;
	src = bprm->p;
	ofs = src % PAGE_SIZE;
	remaining = PAGE_SIZE - src;

	/* Pin and map page */
	page = get_arg_page(bprm, src, 0);
	if (!page) {
		rv = -E2BIG;
		goto out;
	}
	kaddr = kmap(page);
	flush_arg_page(bprm, src & PAGE_MASK, page);

	while (count) {
		bytes = strnlen(kaddr + ofs, remaining);
		/*
		 * If entire string was on this page, include null-terminator
		 * when copying, and count the string.
		 */
		remaining -= bytes;
		if (remaining)
			++bytes, --remaining, --count;
		memcpy(dst, kaddr + ofs, bytes);
		ofs += bytes;
		src += bytes;
		dst += bytes;
		/* Map new page if this one is finished */
		if (!remaining) {
			new_page = get_arg_page(bprm, src, 0);
			if (!new_page) {
				rv = -E2BIG;
				goto out_unmap;
			}

			/* Unmap and unpin old page */
			flush_kernel_dcache_page(page);
			kunmap(page);
			put_arg_page(page);

			page = new_page;
			kaddr = kmap(page);
			flush_arg_page(bprm, src & PAGE_MASK, page);

			ofs = 0;
			remaining = PAGE_SIZE;
		}
	}

	/* Success: return number of bytes copied */
	rv = src - bprm->p;

out_unmap:
	/* Unmap and unpin page */
	flush_kernel_dcache_page(page);
	kunmap(page);
	put_arg_page(page);
out:
	return rv;
}


/*
 * The hooks
 */

/* This is the first hook that runs after the mount tree is initialized */
static int pmsm_socket_create(int family, int type, int protocol, int kern)
{
	if (!relay)
		init_relay();
	return 0;
}

/* Allocates the sb_security structure for this superblock. */
static int pmsm_sb_alloc_security(struct super_block *sb)
{
	struct sb_security *sbs;

	sbs = kzalloc(sizeof(*sbs), GFP_KERNEL);
	if (!sbs)
		return -ENOMEM;

	sb->s_security = sbs;
	return 0;
}

/* Frees the sb_security structure for this superblock. */
static void pmsm_sb_free_security(struct super_block *sb)
{
	struct sb_security *sbs = sb->s_security;

	sb->s_security = NULL;
	kfree(sbs);
}

/*
 * Load the UUID from this filesystem's root inode if there is one, and create a
 * new temporary one if it doesn't support xattrs (e.g. temporary filesystems).
 */
/* Precondition asserted by BUG_ON: sb != NULL */
/* Precondition asserted by get_sb: sb->s_root != NULL */
static int pmsm_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	struct sb_security *sbs;
	struct dentry *d_root;
	struct inode *i_root;
	int rv = 0;

	/* Paranoia sets in... */
	sbs = sb->s_security;
	d_root = dget(sb->s_root);
	i_root = d_root->d_inode;
	if (!i_root->i_op->getxattr) {
		/*
		 * XXX Treats filesystems with no xattr support as new every
		 * time - provenance continuity is lost here!
		 */
		printk(KERN_WARNING "sb_kern_mount: no xattr support "
		                            "for %s\n", sb->s_type->name);
		generate_random_uuid(sbs->uuid);
		goto out;
	}

	mutex_lock(&i_root->i_mutex);

	rv = i_root->i_op->getxattr(d_root, XATTR_NAME_PMSM, sbs->uuid, 16);
	if (rv == 16) {
		rv = 0;
	} else if (rv >= 0 || rv == -ENODATA) {
		/* Only mount filesystems that are correctly labeled */
		printk(KERN_ERR "sb_kern_mount: missing or malformed "
				"UUID label on root!\n");
		rv = -EPERM;
	} else if (rv == -EOPNOTSUPP) {
		/*
		 * Treat as a never-encountered filesystem (apropos for tmpfs,
		 * which throws this error, but XXX not nfs4 which also does)
		 */
		printk(KERN_WARNING "sb_kern_mount: unsupported dev=%s "
				"type=%s\n", sb->s_id, sb->s_type->name);
		generate_random_uuid(sbs->uuid);
		rv = 0;
	} else {
		printk(KERN_ERR "sb_kern_mount: getxattr dev=%s type=%s "
				"err=%d\n", sb->s_id, sb->s_type->name, -rv);
		/* rv from getxattr falls through */
	}

	mutex_unlock(&i_root->i_mutex);
out:
	dput(d_root);
	return rv;
}

/*
 * Initializes a new cred_security object
 */
static int cred_security_init(struct cred_security *csec,
		const struct cred_security *old)
{
	csec->csid = atomic_add_return(1, &csid_current);
	csec->exempt = old ? old->exempt : 0;
	return 0;
}

/*
 * Destroys a cred_security object (called once its refcount falls to zero)
 */
static void cred_security_destroy(struct cred_security *csec)
{
	int id = csec->csid;
	int exempt = csec->exempt;
	struct provmsg_credfree buf;

	kfree(csec);

	if (exempt)
		return;
	buf.header.msgtype = PROVMSG_CREDFREE;
	buf.header.cred_id = id;
	write_to_relay(&buf, sizeof buf);
}

/*
 * Allocate the security part of a blank set of credentials
 */
static int pmsm_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct cred_security *csec;

	csec = kmalloc(sizeof(*csec), gfp);
	if (!csec)
		return -ENOMEM;

	cred->security = csec;
	return 0;
}

/*
 * Free the security part of a set of credentials
 */
static void pmsm_cred_free(struct cred *cred)
{
	struct cred_security *csec = cred->security;

	cred->security = NULL;
	cred_security_destroy(csec);
}

/*
 * Prepare a new set of credentials
 */
static int pmsm_cred_prepare(struct cred *new, const struct cred *old,
                             gfp_t gfp)
{
	const struct cred_security *old_csec;
	struct cred_security *csec;
	struct provmsg_credfork buf;
	int rv;

	csec = kmalloc(sizeof(*csec), gfp);
	if (!csec)
		return -ENOMEM;

	old_csec = old->security;
	rv = cred_security_init(csec, old_csec);
	if (rv)
		goto out_free;
	new->security = csec;

	if (csec->exempt)
		return 0;

	buf.header.msgtype = PROVMSG_CREDFORK;
	buf.header.cred_id = old_csec->csid;
	buf.forked_cred = csec->csid;
	write_to_relay(&buf, sizeof buf);

	return 0;

out_free:
	kfree(csec);
	return rv;
}

/*
 * Copies an existing set of credentials into an already-allocated blank
 * set of credentials.
 */
static void pmsm_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct cred_security *old_csec = old->security;
	struct cred_security *csec = new->security;

	*csec = *old_csec;
	return;
}

/*
 * Install a new set of credentials
 */
static int pmsm_task_fix_setuid(struct cred *new, const struct cred *old,
		int flags)
{
	const struct cred_security *csec = new->security;
	struct provmsg_setid buf;

	if (csec->exempt)
		return cap_task_fix_setuid(new, old, flags);

	csec = new->security;
	buf.header.msgtype = PROVMSG_SETID;
	buf.header.cred_id = csec->csid;
	buf.uid = new->uid;
	buf.gid = new->gid;
	buf.suid = new->suid;
	buf.sgid = new->sgid;
	buf.euid = new->euid;
	buf.egid = new->egid;
	buf.fsuid = new->fsuid;
	buf.fsgid = new->fsgid;
	write_to_relay(&buf, sizeof buf);

	return cap_task_fix_setuid(new, old, flags);
}

/*
 * Run when a process is being transformed by execve.  Has the argv and envp at
 * its disposal, and may be called more than once if there in an interpreter
 * involved.
 */
static int pmsm_bprm_check_security(struct linux_binprm *bprm)
{
	int rv;
	const struct cred_security *cursec = current_security();
	struct cred_security *newsec = bprm->cred->security;
	const struct sb_security *sbs;
	struct provmsg_exec *msg;
	unsigned int bytes;
	char xattr[7];

	/* Allow exempt programs to exec others exempt */
	newsec->exempt = cursec->exempt;
	if (!newsec->exempt && bprm->file && bprm->file->f_dentry &&
			bprm->file->f_dentry->d_inode &&
			bprm->file->f_dentry->d_inode->i_op->getxattr) {
		rv = bprm->file->f_dentry->d_inode->i_op->getxattr(
				bprm->file->f_dentry,
				XATTR_NAME_PMSM, xattr, 7);
		if (rv >= 0 && !strncmp(xattr, "exempt", 6))
			newsec->exempt = 1;
	}

	msg = kmalloc(sizeof (*msg), GFP_KERNEL);
	if (!msg) {
		printk(KERN_ERR "PM/SM: Failed to allocate exec message\n");
		return -ENOMEM;
	}
	rv = bytes = copy_strings_bprm(bprm, msg->argv_envp);
	if (bytes < 0)
		goto out;
	msg->argv_envp_len = bytes;
	msg->header.msgtype = PROVMSG_EXEC;
	msg->header.cred_id = newsec->csid;

	if (bprm->file && bprm->file->f_dentry &&
			bprm->file->f_dentry->d_inode) {
		sbs = bprm->file->f_dentry->d_sb->s_security;
		memcpy(&msg->inode.sb_uuid, &sbs->uuid,
				sizeof (msg->inode.sb_uuid));
		msg->inode.ino = bprm->file->f_dentry->d_inode->i_ino;
	} else {
		printk(KERN_WARNING "PM/SM: Exec on unidentifiable inode?\n");
	}

	write_to_relay(msg, offsetof(struct provmsg_exec, argv_envp) + bytes);
	rv = 0;
out:
	kfree(msg);
	return rv;
}


/*
 * These four hooks, taken together, catch inode creation and deletion
 */
static int pmsm_inode_alloc_security(struct inode *inode)
{
	struct inode_security *isec;

	isec = kzalloc(sizeof *isec, GFP_KERNEL);
	if (!isec)
		return -ENOMEM;
	inode->i_security = isec;
	return 0;
}
static int pmsm_inode_init_security(struct inode *inode, struct inode *dir,
		char **name, void **value, size_t *len)
{
	struct inode_security *isec = inode->i_security;

	isec->is_new = 1;
	return -EOPNOTSUPP;
}
static void pmsm_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	struct inode_security *isec;
	const struct cred_security *cursec;
	const struct sb_security *sbs;
	struct provmsg_inode_alloc allocmsg;
	struct provmsg_setattr attrmsg;
	struct provmsg_link linkmsg;

	if (!inode)
		return;

	isec = inode->i_security;
	if (!isec->is_new)
		return;
	isec->is_new = 0;

	cursec = current_security();

	allocmsg.header.msgtype = PROVMSG_INODE_ALLOC;
	attrmsg.header.msgtype = PROVMSG_SETATTR;
	linkmsg.header.msgtype = PROVMSG_LINK;

	allocmsg.header.cred_id =
		attrmsg.header.cred_id =
		linkmsg.header.cred_id =
		cursec->csid;

	sbs = inode->i_sb->s_security;
	memcpy(allocmsg.inode.sb_uuid, sbs->uuid,
			sizeof allocmsg.inode.sb_uuid);
	allocmsg.inode.ino = inode->i_ino;
	memcpy(&attrmsg.inode, &allocmsg.inode, sizeof attrmsg.inode);
	memcpy(&linkmsg.inode, &allocmsg.inode, sizeof linkmsg.inode);

	attrmsg.mode = inode->i_mode;
	attrmsg.uid = inode->i_uid;
	attrmsg.gid = inode->i_gid;

	linkmsg.dir = dentry->d_parent->d_inode->i_ino;
	linkmsg.fname_len = dentry->d_name.len;
	memcpy(linkmsg.fname, dentry->d_name.name, linkmsg.fname_len);

	write_to_relay(&allocmsg, sizeof allocmsg);
	write_to_relay(&attrmsg, sizeof attrmsg);
	write_to_relay(&linkmsg, offsetof(struct provmsg_link, fname) +
			linkmsg.fname_len);
}
static void pmsm_inode_free_security(struct inode *inode)
{
	const struct cred_security *cursec;
	const struct sb_security *sbs;
	struct provmsg_inode_dealloc msg;

	kfree(inode->i_security);
	if (inode->i_nlink != 0)
		return;

	cursec = current_security();
	msg.header.msgtype = PROVMSG_INODE_DEALLOC;
	msg.header.cred_id = cursec->csid;

	sbs = inode->i_sb->s_security;
	memcpy(msg.inode.sb_uuid, sbs->uuid, sizeof msg.inode.sb_uuid);
	msg.inode.ino = inode->i_ino;

	write_to_relay(&msg, sizeof msg);
}

/*
 * Hooks for tracking name and location of inodes over time.
 */
static int pmsm_inode_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_link msg;

	msg.header.msgtype = PROVMSG_LINK;
	msg.header.cred_id = cursec->csid;

	sbs = old_dentry->d_sb->s_security;
	memcpy(msg.inode.sb_uuid, sbs->uuid, sizeof msg.inode.sb_uuid);
	msg.inode.ino = old_dentry->d_inode->i_ino;
	msg.dir = dir->i_ino;
	msg.fname_len = new_dentry->d_name.len;
	memcpy(msg.fname, new_dentry->d_name.name, msg.fname_len);

	write_to_relay(&msg, offsetof(struct provmsg_link, fname) +
			msg.fname_len);
	return 0;
}
static int pmsm_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_unlink msg;

	msg.header.msgtype = PROVMSG_UNLINK;
	msg.header.cred_id = cursec->csid;

	sbs = dir->i_sb->s_security;
	memcpy(msg.dir.sb_uuid, sbs->uuid, sizeof msg.dir.sb_uuid);
	msg.dir.ino = dir->i_ino;
	msg.fname_len = dentry->d_name.len;
	memcpy(msg.fname, dentry->d_name.name, msg.fname_len);

	write_to_relay(&msg, offsetof(struct provmsg_unlink, fname) +
			msg.fname_len);
	return 0;
}
static int pmsm_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_link linkmsg;
	struct provmsg_unlink unlinkmsg;

	linkmsg.header.msgtype = PROVMSG_LINK;
	unlinkmsg.header.msgtype = PROVMSG_UNLINK;
	linkmsg.header.cred_id =
		unlinkmsg.header.cred_id =
		cursec->csid;

	sbs = old_dentry->d_sb->s_security;
	memcpy(linkmsg.inode.sb_uuid, sbs->uuid, sizeof linkmsg.inode.sb_uuid);
	memcpy(unlinkmsg.dir.sb_uuid, sbs->uuid,
			sizeof unlinkmsg.dir.sb_uuid);
	linkmsg.inode.ino = old_dentry->d_inode->i_ino;

	linkmsg.dir = new_dir->i_ino;
	linkmsg.fname_len = new_dentry->d_name.len;
	memcpy(linkmsg.fname, new_dentry->d_name.name, linkmsg.fname_len);

	unlinkmsg.dir.ino = old_dir->i_ino;
	unlinkmsg.fname_len = old_dentry->d_name.len;
	memcpy(unlinkmsg.fname, old_dentry->d_name.name, unlinkmsg.fname_len);

	write_to_relay(&linkmsg, offsetof(struct provmsg_link, fname) +
			linkmsg.fname_len);
	write_to_relay(&unlinkmsg, offsetof(struct provmsg_unlink, fname) +
			unlinkmsg.fname_len);
	return 0;
}

/*
 * Hook for changes to inode attributes.  Specifically, we're tracking owner,
 * group, and mode.
 */
int pmsm_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	const struct cred_security *cursec;
	const struct sb_security *sbs;
	const struct inode *i;
	struct provmsg_setattr msg;

	if ((attr->ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID)) == 0)
		return 0;

	cursec = current_security();
	msg.header.msgtype = PROVMSG_SETATTR;
	msg.header.cred_id = cursec->csid;

	sbs = dentry->d_sb->s_security;
	memcpy(msg.inode.sb_uuid, sbs->uuid, sizeof msg.inode.sb_uuid);

	i = dentry->d_inode;
	msg.inode.ino = i->i_ino;
	msg.mode = (attr->ia_valid & ATTR_MODE) ? attr->ia_mode : i->i_mode;
	msg.uid = (attr->ia_valid & ATTR_UID) ? attr->ia_uid : i->i_uid;
	msg.gid = (attr->ia_valid & ATTR_GID) ? attr->ia_gid : i->i_gid;

	write_to_relay(&msg, sizeof msg);

	return 0;
}

/*
 * Run at every call to read or write.  The only calls to this function have
 * @mask set to either MAY_READ or MAY_WRITE, nothing else, and never both.
 */
static int pmsm_file_permission(struct file *file, int mask)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_file_p msg;

	if (cursec->exempt)
		return 0;

	msg.header.msgtype = PROVMSG_FILE_P;
	msg.header.cred_id = cursec->csid;

	if (file && file->f_dentry && file->f_dentry->d_inode) {
		sbs = file->f_dentry->d_sb->s_security;
		memcpy(msg.inode.sb_uuid, sbs->uuid, sizeof(msg.inode.sb_uuid));
		msg.inode.ino = file->f_dentry->d_inode->i_ino;
	} else {
		memset(msg.inode.sb_uuid, 0, sizeof(msg.inode.sb_uuid));
		msg.inode.ino = 0;
	}

	msg.mask = mask;
	write_to_relay(&msg, offsetof(struct provmsg_file_p, mask) +
			sizeof(msg.mask));
	return 0;
}

/*
 * Run every time a process maps a file into its memory.  XXX I'm not sure what
 * it means to have a negative dentry on this file.  We must assume that a
 * file's full permissions are used by the resulting memory accesses, e.g. a
 * file mapped read-write is both read and written by the process at all times.
 * TODO: What does this "at all times" imply?  Ouch!
 */
static int pmsm_file_mmap(struct file *file, unsigned long reqprot,
                          unsigned long prot, unsigned long flags,
                          unsigned long addr, unsigned long addr_only)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_mmap msg;

	if (cursec->exempt)
		return 0;

	msg.header.msgtype = PROVMSG_MMAP;
	msg.header.cred_id = cursec->csid;

	if (file && file->f_dentry && file->f_dentry->d_inode) {
		sbs = file->f_dentry->d_sb->s_security;
		memcpy(msg.inode.sb_uuid, sbs->uuid, sizeof(msg.inode.sb_uuid));
		msg.inode.ino = file->f_dentry->d_inode->i_ino;
	} else {
		memset(msg.inode.sb_uuid, 0, sizeof(msg.inode.sb_uuid));
		msg.inode.ino = 0;
	}

	msg.prot = prot;
	msg.flags = flags;
	write_to_relay(&msg, sizeof(msg));
	return 0;
}

/*
 * Hook for inode accesses - called at file open and useful for directory reads
 * which pass provenance from the metadata stored in the directory inode
 * itself.
 */
static int pmsm_inode_permission(struct inode *inode, int mask)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_inode_p msg;

	if (cursec->exempt)
		return 0;

	msg.header.msgtype = PROVMSG_INODE_P;
	msg.header.cred_id = cursec->csid;

	if (inode) {
		sbs = inode->i_sb->s_security;
		memcpy(msg.inode.sb_uuid, sbs->uuid, sizeof(msg.inode.sb_uuid));
		msg.inode.ino = inode->i_ino;
	} else {
		memset(msg.inode.sb_uuid, 0, sizeof(msg.inode.sb_uuid));
		msg.inode.ino = 0;
	}

	msg.mask = mask;
	write_to_relay(&msg, offsetof(struct provmsg_inode_p, mask) +
			sizeof(msg.mask));
	return 0;
}


/*
 * Security alloc/free for individual messages in a message queue
 */
int pmsm_msg_msg_alloc_security(struct msg_msg *msg) {
	struct ipc_security *ipcsec;

	ipcsec = kzalloc(sizeof *ipcsec, GFP_KERNEL);
	if (!ipcsec)
		return -ENOMEM;
	ipcsec->csid = atomic_add_return(1, &ipc_current);
	msg->security = ipcsec;
}

void pmsm_msg_msg_free_security(struct msg_msg *msg) {
	struct ipc_security *ipcsec = msg->security;

	msg->security = NULL;
	kfree(ipcsec);
}

int pmsm_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg,
		int msqflg) {
	const struct cred_security *cursec = current_security();
	const struct ipc_security *ipcsec = msg->security;
	struct provmsgmq_send msg;

	msg.header.msgtype = PROVMSG_MQSEND;
	msg.header.cred_id = cursec->csid;
	msg.ipcid = ipcsec->ipcid;

	write_to_relay(&msg, offsetof(struct provmsg_mqsend, ipcid) +
			sizeof msg.ipcid);
	return 0;
}

int pmsm_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
		struct task_struct *target, long type, int mode) {
	const struct cred_security *cursec = target->cred->security;
	const struct ipc_security *ipcsec = msg->security;
	struct provmsgmq_recv msg;

	msg.header.msgtype = PROVMSG_MQRECV;
	msg.header.cred_id = cursec->csid;
	msg.ipcid = ipcsec->ipcid;

	write_to_relay(&msg, offsetof(struct provmsg_mqrecv, ipcid) +
			sizeof msg.ipcid);
	return 0;
}

int pmsm_shm_alloc_security(struct shmid_kernel *shp);
void pmsm_shm_free_security(struct shmid_kernel *shp);
/* XXX there are permissions on shm, and we aren't logging changes */
int pmsm_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr, int shmflg);

/* XXX figure out how/whether semaphores should be logged */


/*
 * Initialization functions and structures
 */
static void set_init_creds(void)
{
	struct cred *cred = (struct cred *) current->real_cred;
	struct cred_security *csec;

	csec = kzalloc(sizeof *csec, GFP_KERNEL);
	if (!csec)
		panic("PM/SM: Failed to allocate creds for initial task.");
	cred_security_init(csec, NULL);
	cred->security = csec;
}

struct security_operations pmsm_security_ops = {
	.name    = "pmsm",
	HANDLE(socket_create),

	HANDLE(sb_alloc_security),
	HANDLE(sb_free_security),
	HANDLE(sb_kern_mount),

	HANDLE(file_permission),
	HANDLE(file_mmap),
	HANDLE(inode_permission),

	HANDLE(inode_alloc_security),
	HANDLE(inode_init_security),
	HANDLE(d_instantiate),
	HANDLE(inode_free_security),

	HANDLE(inode_link),
	HANDLE(inode_unlink),
	HANDLE(inode_rename),
	HANDLE(inode_setattr),

	HANDLE(msg_msg_alloc_security),
	HANDLE(msg_msg_free_security),
	HANDLE(msg_queue_msgsnd),
	HANDLE(msg_queue_msgrcv),

	HANDLE(cred_alloc_blank),
	HANDLE(cred_free),
	HANDLE(cred_prepare),
	HANDLE(cred_transfer),
	HANDLE(task_fix_setuid),

	HANDLE(bprm_check_security),
};

static int __init pmsm_init(void)
{
	if (!security_module_enable(&pmsm_security_ops)) {
		printk(KERN_ERR "PM/SM: ERROR - failed to enable module\n");
		return -EINVAL;
	}
	printk(KERN_INFO "PM/SM: module enabled\n");

	boot_buffer = kmalloc(BOOT_BUFFER_SIZE, GFP_KERNEL);
	set_init_creds();

	/* Finally register */
	if (register_security(&pmsm_security_ops))
		panic("PM/SM: failed to register operations");

	printk(KERN_INFO "PM/SM: registered\n");
	return 0;
}

security_initcall(pmsm_init);
