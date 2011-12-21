/*
 *  Hi-Fi
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
#include <linux/uaccess.h>

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

#include "hifi.h"
#include "hifi_proto.h"


MODULE_AUTHOR("Devin J. Pohly");
MODULE_LICENSE("GPL");

#define BITS_PER_PAGE (PAGE_SIZE*8)
#define BITS_PER_PAGE_MASK (BITS_PER_PAGE-1)
#define PROVID_MAP_PAGES 4
#define NUM_PROVIDS (PROVID_MAP_PAGES * BITS_PER_PAGE)
static atomic_t provid_free[PROVID_MAP_PAGES] = {
	[0 ... PROVID_MAP_PAGES-1] = ATOMIC_INIT(BITS_PER_PAGE)
};
static void *provid_page[PROVID_MAP_PAGES] = {
	[0 ... PROVID_MAP_PAGES-1] = NULL
};
static int provid_last = -1;

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
			panic("Hi-Fi: Boot buffer overrun");
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
	.header.cred_id = 0,
	.version = HIFI_PROTO_VERSION,
};
static const struct provmsg_setid init_setidmsg = {
	.header.msgtype = PROVMSG_SETID,
	.header.cred_id = 0,
	/* Static, so all IDs are 0 */
};

/* Sets up the relay */
static void init_relay(void)
{
	relay = relay_open("provenance", NULL, (RELAY_TOTAL_SIZE / NUM_RELAYS),
			NUM_RELAYS, &relay_callbacks, NULL);
	if (!relay)
		panic("Hi-Fi: Could not create relay");
	write_to_relay(&init_bootmsg, sizeof(init_bootmsg));
	write_to_relay(&init_setidmsg, sizeof(init_setidmsg));
	printk(KERN_INFO "Hi-Fi: Replaying boot buffer: %uB\n", boot_bytes);
	write_to_relay(boot_buffer, boot_bytes);
	kfree(boot_buffer);
}


/*
 * Function for grabbing the argv and envp from a bprm
 */
static int copy_bytes_bprm(struct linux_binprm *bprm, char *dst,
		unsigned int count)
{
	int rv = 0;
	unsigned int ofs, bytes;
	struct page *page = NULL, *new_page;
	const char *kaddr;
	unsigned long src;

	src = bprm->p;
	ofs = src % PAGE_SIZE;

	while (count) {
		/* Map new page if there's more to come */
		new_page = get_arg_page(bprm, src, 0);
		if (!new_page) {
			rv = -E2BIG;
			goto out_unmap;
		}

		if (page) {
			/* Unmap and unpin old page */
			kunmap(page);
			put_arg_page(page);
		}

		page = new_page;
		kaddr = kmap(page);
		flush_arg_page(bprm, ofs, page);

		bytes = min_t(unsigned int, count, PAGE_SIZE - ofs);
		memcpy(dst, kaddr + ofs, bytes);
		src += bytes;
		dst += bytes;
		count -= bytes;
		ofs = 0;
	}

	/* Success: return number of bytes copied */
	rv = src - bprm->p;

out_unmap:
	if (page) {
		/* Unmap and unpin page */
		kunmap(page);
		put_arg_page(page);
	}
	return rv;
}


/*
 * The hooks
 */

/* This is the first hook that runs after the mount tree is initialized */
static int hifi_socket_create(int family, int type, int protocol, int kern)
{
	if (!relay)
		init_relay();
	return 0;
}

/* Allocates the sb_security structure for this superblock. */
static int hifi_sb_alloc_security(struct super_block *sb)
{
	struct sb_security *sbs;

	sbs = kzalloc(sizeof(*sbs), GFP_KERNEL);
	if (!sbs)
		return -ENOMEM;

	sb->s_security = sbs;
	return 0;
}

/* Frees the sb_security structure for this superblock. */
static void hifi_sb_free_security(struct super_block *sb)
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
static int hifi_sb_kern_mount(struct super_block *sb, int flags, void *data)
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
		printk(KERN_WARNING "Hi-Fi: no xattr support for "
		                            "%s\n", sb->s_type->name);
		generate_random_uuid(sbs->uuid);
		goto out;
	}

	mutex_lock(&i_root->i_mutex);

	rv = i_root->i_op->getxattr(d_root, XATTR_NAME_HIFI, sbs->uuid, 16);
	if (rv == 16) {
		rv = 0;
	} else if (rv >= 0 || rv == -ENODATA) {
		/* Only mount filesystems that are correctly labeled */
		printk(KERN_ERR "Hi-Fi: Missing or malformed UUID label "
				"on filesystem.  If this is\n");
		printk(KERN_ERR "       your root filesystem, kernel may "
				"panic or drop to initrd.\n");
		rv = -EPERM;
	} else if (rv == -EOPNOTSUPP) {
		/*
		 * Treat as a never-encountered filesystem (apropos for tmpfs,
		 * which throws this error, but XXX not nfs4 which also does)
		 */
		printk(KERN_WARNING "Hi-Fi: getxattr unsupported dev=%s "
				"type=%s\n", sb->s_id, sb->s_type->name);
		generate_random_uuid(sbs->uuid);
		rv = 0;
	} else {
		printk(KERN_ERR "Hi-Fi: getxattr dev=%s type=%s "
				"err=%d\n", sb->s_id, sb->s_type->name, -rv);
		/* rv from getxattr falls through */
	}

	mutex_unlock(&i_root->i_mutex);
out:
	dput(d_root);
	return rv;
}

/*
 * Sets up the identifier map
 */
static int init_provid_map(void)
{
	int i;
	void *page;

	for (i = 0; i < PROVID_MAP_PAGES; i++) {
		page = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (unlikely(!page)) {
			while (--i >= 0)
				kfree(provid_page[i]);
			return -ENOMEM;
		}
		provid_page[i] = page;
	}
	return 0;
}

/*
 * Returns the next available identifier.  Adapted from alloc_pidmap in
 * kernel/pid.c.
 */
static int alloc_provid(void)
{
	int i, offset, page, max_scan, id, last = provid_last;

	id = last + 1;
	if (id >= NUM_PROVIDS)
		id = 0;
	offset = id & BITS_PER_PAGE_MASK;
	page = id / BITS_PER_PAGE;
	max_scan = PROVID_MAP_PAGES - !offset;

	for (i = 0; i <= max_scan; i++) {
		if (likely(atomic_read(&provid_free[page]))) {
			do {
				if (!test_and_set_bit(offset,
							provid_page[page])) {
					atomic_dec(&provid_free[page]);
					provid_last = id;
					return id;
				}
				offset = find_next_zero_bit(provid_page[page],
						BITS_PER_PAGE, offset);
				id = page * BITS_PER_PAGE + offset;
			} while (offset < BITS_PER_PAGE && id < NUM_PROVIDS &&
					(i != max_scan || id < last ||
					 !((last+1) & BITS_PER_PAGE_MASK)));
		}
		if (page < PROVID_MAP_PAGES)
			page++;
		else
			page = 0;
		offset = 0;
		id = page * BITS_PER_PAGE;
	}
	return -1;
}

/*
 * Frees a provenance identifier.  Adapted from free_pidmap in kernel/pid.c.
 */
static void free_provid(int id) {
	int offset, page;
	offset = id & BITS_PER_PAGE_MASK;
	page = id / BITS_PER_PAGE;

	clear_bit(offset, provid_page[page]);
	atomic_inc(&provid_free[page]);
}

/*
 * Initializes a new cred_security object
 */
static int cred_security_init(struct cred_security *csec,
		const struct cred_security *old)
{
	struct provmsg_credfork buf;
	csec->flags = CSEC_INITED;

	buf.header.msgtype = PROVMSG_CREDFORK;
	buf.header.cred_id = old->csid;
	buf.forked_cred = csec->csid;
	write_to_relay(&buf, sizeof(buf));
	return 0;
}

/*
 * Destroys a cred_security object (called once its refcount falls to zero)
 */
static void cred_security_destroy(struct kref *ref)
{
	struct cred_security *csec = container_of(ref, struct cred_security,
			refcount);
	int id = csec->csid;
	int inited = csec->flags & CSEC_INITED;
	struct provmsg_credfree buf;

	kfree(csec);
	free_provid(id);

	if (!inited)
		return;
	buf.header.msgtype = PROVMSG_CREDFREE;
	buf.header.cred_id = id;
	write_to_relay(&buf, sizeof(buf));
}

/*
 * Free the security part of a set of credentials
 */
static void hifi_cred_free(struct cred *cred)
{
	struct cred_security *csec = cred->security;

	cred->security = NULL;
	kref_put(&csec->refcount, cred_security_destroy);
}

/*
 * Prepare a new set of credentials
 */
static int hifi_cred_prepare(struct cred *new, const struct cred *old,
                             gfp_t gfp)
{
	struct cred_security *old_csec = old->security;
	struct cred_security *csec;
	int rv, id;

	if (unlikely(old_csec->flags & CSEC_EXEMPT)) {
		kref_get(&old_csec->refcount);
		new->security = old_csec;
		return 0;
	}
	csec = kmalloc(sizeof(*csec), gfp);
	if (!csec)
		return -ENOMEM;

	rv = -ENOMEM;
	id = alloc_provid();
	if (id < 0)
		goto out_free;
	csec->csid = id;
	kref_init(&csec->refcount);
	rv = cred_security_init(csec, old_csec);
	if (rv)
		goto out_free_id;

	new->security = csec;
	return 0;

out_free_id:
	free_provid(id);
out_free:
	kfree(csec);
	return rv;
}

/*
 * Allocate the security part of a blank set of credentials - used only with
 * cred_transfer in the context of keys
 */
static int hifi_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct cred_security *csec;
	int id;

	csec = kzalloc(sizeof(*csec), gfp);
	if (!csec)
		return -ENOMEM;

	id = alloc_provid();
	if (id < 0)
		return -ENOMEM;
	csec->csid = id;
	kref_init(&csec->refcount);
	/* i.e. not inited */
	csec->flags = 0;

	cred->security = csec;
	return 0;
}

/*
 * Copies an existing set of credentials into an already-allocated blank
 * set of credentials - used only with cred_alloc_blank in the context of keys
 */
static void hifi_cred_transfer(struct cred *new, const struct cred *old)
{
	struct cred_security *old_csec = old->security;
	struct cred_security *csec = new->security;

	if (unlikely(old_csec->flags & CSEC_EXEMPT)) {
		free_provid(csec->csid);
		kfree(csec);
		kref_get(&old_csec->refcount);
		new->security = old_csec;
	} else {
		cred_security_init(csec, old_csec);
	}
	return;
}

/*
 * Install a new set of credentials
 */
static int hifi_task_fix_setuid(struct cred *new, const struct cred *old,
		int flags)
{
	const struct cred_security *csec = new->security;
	struct provmsg_setid buf;

	if (csec->flags & CSEC_EXEMPT)
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
	write_to_relay(&buf, sizeof(buf));

	return cap_task_fix_setuid(new, old, flags);
}

/*
 * Run when a process is being transformed by execve.  Has the argv and envp at
 * its disposal, and may be called more than once if there in an interpreter
 * involved.
 */
static int hifi_bprm_check_security(struct linux_binprm *bprm)
{
	int rv;
	const struct cred_security *cursec = current_security();
	struct cred_security *newsec = bprm->cred->security;
	const struct sb_security *sbs;
	struct provmsg_exec *msg;
	char xattr[7];
	unsigned long bytes;

	/* Don't worry about the internal forkings etc. of exempt programs */
	if (cursec->flags & CSEC_EXEMPT)
		return 0;

	/* Examination of exec.c:open_exec() shows that nothing in this
	 * expression can be NULL */
	if (bprm->file->f_dentry->d_inode->i_op->getxattr) {
		rv = bprm->file->f_dentry->d_inode->i_op->getxattr(
				bprm->file->f_dentry,
				XATTR_NAME_HIFI, xattr, 7);
		if (rv >= 0 && !strncmp(xattr, "exempt", 6))
			newsec->flags |= CSEC_EXEMPT;
	}

	bytes = bprm->exec - bprm->p;
	msg = kmalloc(sizeof(*msg) + bytes, GFP_KERNEL);
	if (!msg) {
		printk(KERN_ERR "Hi-Fi: Failed to allocate exec message\n");
		return -ENOMEM;
	}
	rv = copy_bytes_bprm(bprm, msg->argv_envp, bytes);
	if (rv < 0) {
		printk(KERN_ERR "Hi-Fi: Exec copy failed %d\n", rv);
		goto out;
	}
	msg->argv_envp_len = bytes;
	msg->argc = bprm->argc;
	msg->header.msgtype = PROVMSG_EXEC;
	msg->header.cred_id = newsec->csid;

	sbs = bprm->file->f_dentry->d_sb->s_security;
	memcpy(msg->inode.sb_uuid, sbs->uuid, sizeof(msg->inode.sb_uuid));
	msg->inode.ino = bprm->file->f_dentry->d_inode->i_ino;

	write_to_relay(msg, sizeof(*msg) + msg->argv_envp_len);
	rv = 0;
out:
	kfree(msg);
	return rv;
}


/*
 * Inode creation and deletion
 */
static int hifi_inode_init_security(struct inode *inode, struct inode *dir,
		const struct qstr *qstr, char **name, void **value, size_t *len)
{
	const struct cred_security *cursec;
	const struct sb_security *sbs;
	struct provmsg_inode_alloc allocmsg;
	struct provmsg_setattr attrmsg;
	struct provmsg_link *linkmsg;

	linkmsg = kmalloc(sizeof(*linkmsg) + qstr->len, GFP_KERNEL);
	if (!linkmsg) {
		printk(KERN_ERR "Hi-Fi: Failed to allocate link msg\n");
		return -ENOMEM;
	}

	cursec = current_security();
	sbs = inode->i_sb->s_security;

	allocmsg.header.msgtype = PROVMSG_INODE_ALLOC;
	allocmsg.header.cred_id = cursec->csid;

	attrmsg.header.msgtype = PROVMSG_SETATTR;
	attrmsg.header.cred_id = cursec->csid;

	linkmsg->header.msgtype = PROVMSG_LINK;
	linkmsg->header.cred_id = cursec->csid;

	memcpy(allocmsg.inode.sb_uuid, sbs->uuid,
			sizeof(allocmsg.inode.sb_uuid));
	allocmsg.inode.ino = inode->i_ino;
	memcpy(&attrmsg.inode, &allocmsg.inode, sizeof(attrmsg.inode));
	memcpy(&linkmsg->inode, &allocmsg.inode, sizeof(linkmsg->inode));

	attrmsg.uid = inode->i_uid;
	attrmsg.gid = inode->i_gid;
	attrmsg.mode = inode->i_mode;

	linkmsg->dir = dir->i_ino;
	linkmsg->fname_len = qstr->len;
	memcpy(linkmsg->fname, qstr->name, linkmsg->fname_len);

	write_to_relay(&allocmsg, sizeof(allocmsg));
	write_to_relay(&attrmsg, sizeof(attrmsg));
	write_to_relay(linkmsg, sizeof(*linkmsg) + linkmsg->fname_len);
	kfree(linkmsg);

	return -EOPNOTSUPP;
}

static void hifi_inode_free_security(struct inode *inode)
{
	const struct cred_security *cursec;
	const struct sb_security *sbs;
	struct provmsg_inode_dealloc msg;

	if (inode->i_nlink != 0)
		return;

	cursec = current_security();
	msg.header.msgtype = PROVMSG_INODE_DEALLOC;
	msg.header.cred_id = cursec->csid;

	sbs = inode->i_sb->s_security;
	memcpy(msg.inode.sb_uuid, sbs->uuid, sizeof(msg.inode.sb_uuid));
	msg.inode.ino = inode->i_ino;

	write_to_relay(&msg, sizeof(msg));
}

/*
 * Hooks for tracking name and location of inodes over time.
 */
static int hifi_inode_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_link *msg;

	msg = kmalloc(sizeof(*msg) + new_dentry->d_name.len, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg->header.msgtype = PROVMSG_LINK;
	msg->header.cred_id = cursec->csid;

	sbs = old_dentry->d_sb->s_security;
	memcpy(msg->inode.sb_uuid, sbs->uuid, sizeof(msg->inode.sb_uuid));
	msg->inode.ino = old_dentry->d_inode->i_ino;
	msg->dir = dir->i_ino;
	msg->fname_len = new_dentry->d_name.len;
	memcpy(msg->fname, new_dentry->d_name.name, msg->fname_len);

	write_to_relay(msg, sizeof(*msg) + msg->fname_len);
	kfree(msg);
	return 0;
}

static int hifi_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_unlink *msg;

	msg = kmalloc(sizeof(*msg) + dentry->d_name.len, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg->header.msgtype = PROVMSG_UNLINK;
	msg->header.cred_id = cursec->csid;

	sbs = dir->i_sb->s_security;
	memcpy(msg->dir.sb_uuid, sbs->uuid, sizeof(msg->dir.sb_uuid));
	msg->dir.ino = dir->i_ino;
	msg->fname_len = dentry->d_name.len;
	memcpy(msg->fname, dentry->d_name.name, msg->fname_len);

	write_to_relay(msg, sizeof(*msg) + msg->fname_len);
	kfree(msg);
	return 0;
}

static int hifi_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_link *linkmsg;
	struct provmsg_unlink *unlinkmsg;

	linkmsg = kmalloc(sizeof(*linkmsg) + new_dentry->d_name.len, GFP_KERNEL);
	if (!linkmsg)
		return -ENOMEM;
	unlinkmsg = kmalloc(sizeof(*unlinkmsg) + old_dentry->d_name.len,
			GFP_KERNEL);
	if (!unlinkmsg) {
		kfree(linkmsg);
		return -ENOMEM;
	}

	linkmsg->header.msgtype = PROVMSG_LINK;
	unlinkmsg->header.msgtype = PROVMSG_UNLINK;
	linkmsg->header.cred_id =
		unlinkmsg->header.cred_id =
		cursec->csid;

	sbs = old_dentry->d_sb->s_security;
	memcpy(linkmsg->inode.sb_uuid, sbs->uuid,
			sizeof(linkmsg->inode.sb_uuid));
	memcpy(unlinkmsg->dir.sb_uuid, sbs->uuid,
			sizeof(unlinkmsg->dir.sb_uuid));
	linkmsg->inode.ino = old_dentry->d_inode->i_ino;

	linkmsg->dir = new_dir->i_ino;
	linkmsg->fname_len = new_dentry->d_name.len;
	memcpy(linkmsg->fname, new_dentry->d_name.name, linkmsg->fname_len);

	unlinkmsg->dir.ino = old_dir->i_ino;
	unlinkmsg->fname_len = old_dentry->d_name.len;
	memcpy(unlinkmsg->fname, old_dentry->d_name.name, unlinkmsg->fname_len);

	write_to_relay(linkmsg, sizeof(*linkmsg) + linkmsg->fname_len);
	write_to_relay(unlinkmsg, sizeof(*unlinkmsg) + unlinkmsg->fname_len);
	kfree(unlinkmsg);
	kfree(linkmsg);
	return 0;
}

/*
 * Hook for changes to inode attributes.  Specifically, we're tracking owner,
 * group, and mode.
 */
int hifi_inode_setattr(struct dentry *dentry, struct iattr *attr)
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
	memcpy(msg.inode.sb_uuid, sbs->uuid, sizeof(msg.inode.sb_uuid));

	i = dentry->d_inode;
	msg.inode.ino = i->i_ino;
	msg.uid = (attr->ia_valid & ATTR_UID) ? attr->ia_uid : i->i_uid;
	msg.gid = (attr->ia_valid & ATTR_GID) ? attr->ia_gid : i->i_gid;
	msg.mode = (attr->ia_valid & ATTR_MODE) ? attr->ia_mode : i->i_mode;

	write_to_relay(&msg, sizeof(msg));

	return 0;
}

/*
 * Run at every call to read or write.  The only calls to this function have
 * @mask set to either MAY_READ or MAY_WRITE, nothing else, and never both.
 */
static int hifi_file_permission(struct file *file, int mask)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_file_p msg;

	if (cursec->flags & CSEC_EXEMPT)
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
	write_to_relay(&msg, sizeof(msg));
	return 0;
}

/*
 * Run every time a process maps a file into its memory.  XXX I'm not sure what
 * it means to have a negative dentry on this file.  We must assume that a
 * file's full permissions are used by the resulting memory accesses, e.g. a
 * file mapped read-write is both read and written by the process at all times.
 * TODO: What does this "at all times" imply?  Ouch!
 */
static int hifi_file_mmap(struct file *file, unsigned long reqprot,
                          unsigned long prot, unsigned long flags,
                          unsigned long addr, unsigned long addr_only)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_mmap msg;

	if (cursec->flags & CSEC_EXEMPT)
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
static int hifi_inode_permission(struct inode *inode, int mask)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_inode_p msg;

	if (cursec->flags & CSEC_EXEMPT)
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
	write_to_relay(&msg, sizeof(msg));
	return 0;
}


/*
 * Security alloc/free for individual messages in a message queue
 */
static int hifi_msg_msg_alloc_security(struct msg_msg *msg) {
	struct msg_security *msgsec;

	msgsec = kzalloc(sizeof(*msgsec), GFP_KERNEL);
	if (!msgsec)
		return -ENOMEM;
	msgsec->msgid = alloc_provid();
	msg->security = msgsec;
	return 0;
}

static void hifi_msg_msg_free_security(struct msg_msg *msg) {
	struct msg_security *msgsec = msg->security;
	int id = msgsec->msgid;

	msg->security = NULL;
	kfree(msgsec);
	free_provid(id);
}

static int hifi_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg,
		int msqflg) {
	const struct cred_security *cursec = current_security();
	const struct msg_security *msgsec = msg->security;
	struct provmsg_mqsend logmsg;

	logmsg.header.msgtype = PROVMSG_MQSEND;
	logmsg.header.cred_id = cursec->csid;
	logmsg.msgid = msgsec->msgid;

	write_to_relay(&logmsg, sizeof(logmsg));
	return 0;
}

static int hifi_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
		struct task_struct *target, long type, int mode) {
	const struct cred_security *cursec = target->cred->security;
	const struct msg_security *msgsec = msg->security;
	struct provmsg_mqrecv logmsg;

	logmsg.header.msgtype = PROVMSG_MQRECV;
	logmsg.header.cred_id = cursec->csid;
	logmsg.msgid = msgsec->msgid;

	write_to_relay(&logmsg, sizeof(logmsg));
	return 0;
}


/*
 * Initialization functions and structures
 */
static int set_init_creds(void)
{
	struct cred *cred = (struct cred *) current->real_cred;
	struct cred_security *csec;
	int id;

	csec = kzalloc(sizeof(*csec), GFP_KERNEL);
	if (!csec)
		return -ENOMEM;

	id = alloc_provid();
	if (id < 0)
		goto out_nomem;
	csec->csid = id;
	kref_init(&csec->refcount);
	csec->flags = CSEC_INITED;

	cred->security = csec;
	return 0;

out_nomem:
	kfree(csec);
	return -ENOMEM;
}

struct security_operations hifi_security_ops = {
	.name    = "hifi",
	HANDLE(socket_create),

	HANDLE(sb_alloc_security),
	HANDLE(sb_free_security),
	HANDLE(sb_kern_mount),

	HANDLE(file_permission),
	HANDLE(file_mmap),
	HANDLE(inode_permission),

	HANDLE(inode_init_security),
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

static int __init hifi_init(void)
{
	int rv = 0;

	if (!security_module_enable(&hifi_security_ops)) {
		printk(KERN_ERR "Hi-Fi: ERROR - failed to enable module\n");
		return -EINVAL;
	}
	printk(KERN_INFO "Hi-Fi: module enabled\n");

	boot_buffer = kmalloc(BOOT_BUFFER_SIZE, GFP_KERNEL);
	rv = init_provid_map();
	if (rv)
		return rv;
	if (set_init_creds())
		panic("Hi-Fi: Failed to allocate creds for initial task.");

	/* Finally register */
	if (register_security(&hifi_security_ops))
		panic("Hi-Fi: failed to register operations");

	printk(KERN_INFO "Hi-Fi: registered\n");
	return 0;
}

security_initcall(hifi_init);
