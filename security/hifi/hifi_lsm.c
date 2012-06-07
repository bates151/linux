/*
 *  Hi-Fi
 *
 *  Monitors provenance at the LSM layer.
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
#include <linux/uuid.h>

/* for relay support */
#include <linux/debugfs.h>
#include <linux/relay.h>
#include <linux/spinlock.h>

/* for UNIX domain sockets */
#include <linux/net.h>
#include <net/sock.h>
#include <net/af_unix.h>

/* for IP sockets */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "hifi.h"
#include "hifi_proto.h"


MODULE_AUTHOR("Devin J. Pohly");
MODULE_DESCRIPTION("High-fidelity provenance monitor");
MODULE_LICENSE("GPL");


int bufs = 32;
int buf_size_shift = 20;
int boot_buf_size = 1024;

module_param(bufs, int, 0);
module_param(buf_size_shift, int, 0);
module_param(boot_buf_size, int, 0);

MODULE_PARM_DESC(bufs, "Number of relay sub-buffers for provenance data (default: 32)");
MODULE_PARM_DESC(buf_size_shift, "Log base 2 of sub-buffer size (default: 20=1MiB");
MODULE_PARM_DESC(boot_buf_size, "Size of temporary boot buffer (default: 1024)");


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

static char *boot_buffer;
static unsigned boot_bytes = 0;
static struct rchan *relay;
static DEFINE_SPINLOCK(relay_lock);

static atomic64_t sock_counter = ATOMIC64_INIT(0);


/******************************************************************************
 *
 * RELAY SETUP
 *
 ******************************************************************************/

/*
 * Writes to the relay
 */
static void write_to_relay(const void *data, size_t length)
{
	unsigned long flags;
	spin_lock_irqsave(&relay_lock, flags);
	if (unlikely(!relay)) {
		if (boot_bytes + length > boot_buf_size)
			panic("Hi-Fi: Boot buffer overrun");
		memcpy(boot_buffer + boot_bytes, data, length);
		boot_bytes += length;
	} else {
		relay_write(relay, data, length);
	}
	spin_unlock_irqrestore(&relay_lock, flags);
}

/*
 * Implementation of relay behavior
 */
static struct dentry *relay_dentry;

static struct dentry *relay_create_file(const char *filename,
		struct dentry *parent, int mode, struct rchan_buf *buf,
		int *is_global)
{
	*is_global = 1;
	relay_dentry = dget(debugfs_create_file(filename, mode, parent, buf,
			&relay_file_operations));
	return relay_dentry;
}

static int relay_remove_file(struct dentry *dentry)
{
	dput(relay_dentry);
	debugfs_remove(dentry);
	return 0;
}

static int relay_subbuf_start(struct rchan_buf *buf, void *subbuf,
		void *prev_subbuf, size_t prev_padding)
{
	/* Prevent loss of provenance data */
	if (relay_buf_full(buf))
		panic("Hi-Fi: no space left in relay!");
	return 1;
}

static struct rchan_callbacks relay_callbacks = {
	.create_buf_file = relay_create_file,
	.remove_buf_file = relay_remove_file,
	.subbuf_start = relay_subbuf_start
};

/* Initial messages */
static uuid_be boot_uuid;
static __initdata struct provmsg_boot init_bootmsg = {
	.msg.len_lo = MSGLEN_LO(sizeof(struct provmsg_boot)),
	.msg.len_hi = MSGLEN_HI(sizeof(struct provmsg_boot)),
	.msg.type = PROVMSG_BOOT,
	.msg.cred_id = 0,
	/* .uuid is {0} to start with */
};

static __initdata struct provmsg_setid init_setidmsg = {
	.msg.len_lo = MSGLEN_LO(sizeof(struct provmsg_setid)),
	.msg.len_hi = MSGLEN_HI(sizeof(struct provmsg_setid)),
	.msg.type = PROVMSG_SETID,
	.msg.cred_id = 0,
	/* Static, so all IDs are (correctly) inited to 0=root */
};

/*
 * Sets up the relay
 */
static int __init hifi_init_relay(void)
{
	relay = relay_open("provenance", NULL, (1 << buf_size_shift),
			bufs, &relay_callbacks, NULL);
	if (!relay)
		panic("Hi-Fi: Could not create relay");
	init_bootmsg.uuid = boot_uuid;
	write_to_relay(&init_bootmsg, sizeof(init_bootmsg));
	write_to_relay(&init_setidmsg, sizeof(init_setidmsg));
	printk(KERN_INFO "Hi-Fi: Replaying boot buffer: %uB\n", boot_bytes);
	write_to_relay(boot_buffer, boot_bytes);
	kfree(boot_buffer);
	return 0;
}
core_initcall(hifi_init_relay);


/******************************************************************************
 *
 * HELPER FUNCTIONS
 *
 ******************************************************************************/

/*
 * Grabs the argv and envp from a bprm.
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
 * Returns the next socket ID for this system.
 */
static void next_sockid(struct sockid *label)
{
	u64 counter = atomic64_inc_return(&sock_counter);
	label->high = counter >> 32;
	label->low = counter & ((1LL << 32) - 1);
}

/*
 * Finds the label in a set of options.
 */
static u8 *find_packet_label(u8 *opts, int len)
{
	u8 *p = opts;
	while (p < opts + len)
		switch (p[0]) {
		case IPOPT_HIFI:
			/* Make sure it's the right length */
			if (p + sizeof(struct sockid_opt) > opts + len ||
					p[1] != sizeof(struct sockid_opt))
				return NULL;
			return p;
		case IPOPT_END:
			return NULL;
		case IPOPT_NOOP:
			p++;
			break;
		default:
			if (p[1] < 2)
				return NULL;
			p += p[1];
			break;
		}
	return NULL;
}

/*
 * Removes the label from the packet in @skb and returns it in @label.
 */
static int detach_packet_label(struct sk_buff *skb, struct host_sockid *label)
{
	struct iphdr *iph = ip_hdr(skb);
	u8 *p = find_packet_label((u8 *) (iph + 1), (iph->ihl - 5) * 4);
	if (!p)
		return -1;

	*label = *((struct host_sockid *) (p + 2));

	memmove(skb_pull(skb, sizeof(struct sockid_opt)), iph, p - (u8 *) iph);
	skb_reset_network_header(skb);

	/* Do a little fixup... */
	iph = ip_hdr(skb);
	iph->tot_len -= sizeof(struct sockid_opt);
	iph->ihl -= sizeof(struct sockid_opt) / 4;
	ip_send_check(iph);
	return 0;
}

/*
 * Adds a label to the packet in skb.
 */
static int label_packet(struct sk_buff *skb, const struct sockid *label)
{
	struct iphdr *iph = ip_hdr(skb);
	struct host_sockid *lp;
	u8 *p;

	p = find_packet_label((u8 *) (iph + 1), (iph->ihl - 5) * 4);
	if (!p) {
		/* No data, don't worry about it */
		if (skb->data_len == 0)
			return 0;
		printk(KERN_WARNING "Hi-Fi: no space found for packet label!\n");
		return 0;
	}

	/* Write label and fix checksum */
	lp = (struct host_sockid *) (p + 2);
	lp->host = boot_uuid;
	lp->sock = *label;
	ip_send_check(iph);
	return 0;
}


/******************************************************************************
 *
 * PROCESS/THREAD HOOKS
 *
 ******************************************************************************/

/*
 * Initializes a new cred_security object
 */
static void cred_security_init(struct cred_security *csec,
		const struct cred_security *old)
{
	struct provmsg_credfork buf;
	csec->flags = CSEC_INITED;

	msg_initlen(&buf.msg, sizeof(buf));
	buf.msg.type = PROVMSG_CREDFORK;
	buf.msg.cred_id = old->csid;
	buf.forked_cred = csec->csid;
	write_to_relay(&buf, sizeof(buf));
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
	msg_initlen(&buf.msg, sizeof(buf));
	buf.msg.type = PROVMSG_CREDFREE;
	buf.msg.cred_id = id;
	write_to_relay(&buf, sizeof(buf));
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

	if (unlikely(old_csec->flags & CSEC_OPAQUE)) {
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
	cred_security_init(csec, old_csec);

	new->security = csec;
	return 0;

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
 * Free the security part of a set of credentials
 */
static void hifi_cred_free(struct cred *cred)
{
	struct cred_security *csec = cred->security;

	cred->security = NULL;
	kref_put(&csec->refcount, cred_security_destroy);
}

/*
 * Copies an existing set of credentials into an already-allocated blank
 * set of credentials - used only with cred_alloc_blank in the context of keys
 */
static void hifi_cred_transfer(struct cred *new, const struct cred *old)
{
	struct cred_security *old_csec = old->security;
	struct cred_security *csec = new->security;

	if (unlikely(old_csec->flags & CSEC_OPAQUE)) {
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

	if (csec->flags & CSEC_OPAQUE)
		return cap_task_fix_setuid(new, old, flags);

	msg_initlen(&buf.msg, sizeof(buf));
	buf.msg.type = PROVMSG_SETID;
	buf.msg.cred_id = csec->csid;
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
	unsigned long len;

	/* Don't worry about the internal forkings etc. of opaque programs */
	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	/* Examination of exec.c:open_exec() shows that nothing in this
	 * expression can be NULL */
	if (bprm->file->f_dentry->d_inode->i_op->getxattr) {
		rv = bprm->file->f_dentry->d_inode->i_op->getxattr(
				bprm->file->f_dentry,
				XATTR_NAME_HIFI, xattr, 7);
		if (rv >= 0 && !strncmp(xattr, "opaque", 6))
			newsec->flags |= CSEC_OPAQUE;
	}

	len = bprm->exec - bprm->p;
	msg = kmalloc(sizeof(*msg) + len, GFP_KERNEL);
	if (!msg) {
		printk(KERN_ERR "Hi-Fi: Failed to allocate exec message\n");
		return -ENOMEM;
	}
	rv = copy_bytes_bprm(bprm, msg->argv_envp, len);
	if (rv < 0) {
		printk(KERN_ERR "Hi-Fi: Exec copy failed %d\n", rv);
		goto out;
	}
	msg_initlen(&msg->msg, sizeof(*msg) + len);
	msg->msg.type = PROVMSG_EXEC;
	msg->msg.cred_id = newsec->csid;
	msg->argc = bprm->argc;

	sbs = bprm->file->f_dentry->d_sb->s_security;
	msg->inode.sb_uuid = sbs->uuid;
	msg->inode.ino = bprm->file->f_dentry->d_inode->i_ino;

	write_to_relay(msg, sizeof(*msg) + len);
	rv = 0;
out:
	kfree(msg);
	return rv;
}

/*
 * Committing (and possibly changing) credentials at process execution
 */
static void hifi_bprm_committing_creds(struct linux_binprm *bprm)
{
	const struct cred_security *csec = bprm->cred->security;
	struct provmsg_setid buf;

	if (csec->flags & CSEC_OPAQUE)
		return;

	msg_initlen(&buf.msg, sizeof(buf));
	buf.msg.type = PROVMSG_SETID;
	buf.msg.cred_id = csec->csid;
	buf.uid = bprm->cred->uid;
	buf.gid = bprm->cred->gid;
	buf.suid = bprm->cred->suid;
	buf.sgid = bprm->cred->sgid;
	buf.euid = bprm->cred->euid;
	buf.egid = bprm->cred->egid;
	buf.fsuid = bprm->cred->fsuid;
	buf.fsgid = bprm->cred->fsgid;
	write_to_relay(&buf, sizeof(buf));
}


/******************************************************************************
 *
 * FILESYSTEM HOOKS
 *
 ******************************************************************************/

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
	if (!i_root->i_op->getxattr ||
			!strcmp("tmpfs", sb->s_type->name) ||
			!strcmp("devtmpfs", sb->s_type->name)) {
		/*
		 * XXX Treats filesystems with no xattr support as new every
		 * time - provenance continuity is lost here!
		 */
		printk(KERN_WARNING "Hi-Fi: no xattr/tmpfs: "
		                            "%s\n", sb->s_type->name);
		generate_random_uuid(sbs->uuid.b);
		goto out;
	}

	mutex_lock(&i_root->i_mutex);
	rv = i_root->i_op->getxattr(d_root, XATTR_NAME_HIFI, &sbs->uuid, 16);
	mutex_unlock(&i_root->i_mutex);

	if (rv == 16) {
		rv = 0;
	} else if (rv >= 0 || rv == -ENODATA) {
		/* Only mount filesystems that are correctly labeled */
		printk(KERN_ERR "Hi-Fi: Missing or malformed UUID label "
				"on filesystem.  If this is\n");
		printk(KERN_ERR "       your root filesystem, kernel may "
				"panic or drop to initrd.\n");
		rv = -EPERM;
	} else {
		printk(KERN_ERR "Hi-Fi: getxattr dev=%s type=%s "
				"err=%d\n", sb->s_id, sb->s_type->name, -rv);
		/* rv from getxattr falls through */
	}
out:
	dput(d_root);
	return rv;
}

/*
 * Creating an inode
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

	msg_initlen(&allocmsg.msg, sizeof(allocmsg));
	allocmsg.msg.type = PROVMSG_INODE_ALLOC;
	allocmsg.msg.cred_id = cursec->csid;
	allocmsg.inode.sb_uuid = sbs->uuid;
	allocmsg.inode.ino = inode->i_ino;

	msg_initlen(&attrmsg.msg, sizeof(attrmsg));
	attrmsg.msg.type = PROVMSG_SETATTR;
	attrmsg.msg.cred_id = cursec->csid;
	attrmsg.inode = allocmsg.inode;
	attrmsg.uid = inode->i_uid;
	attrmsg.gid = inode->i_gid;
	attrmsg.mode = inode->i_mode;

	msg_initlen(&linkmsg->msg, sizeof(*linkmsg) + qstr->len);
	linkmsg->msg.type = PROVMSG_LINK;
	linkmsg->msg.cred_id = cursec->csid;
	linkmsg->inode = allocmsg.inode;
	linkmsg->dir = dir->i_ino;
	memcpy(linkmsg->fname, qstr->name, qstr->len);

	// XXX allocate one block and write as a unit
	write_to_relay(&allocmsg, sizeof(allocmsg));
	write_to_relay(&attrmsg, sizeof(attrmsg));
	write_to_relay(linkmsg, sizeof(*linkmsg) + qstr->len);
	kfree(linkmsg);

	return -EOPNOTSUPP;
}

/*
 * Deleting an inode (when nlink hits 0)
 */
static void hifi_inode_free_security(struct inode *inode)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs = inode->i_sb->s_security;
	struct provmsg_inode_dealloc msg;

	if (inode->i_nlink != 0)
		return;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_INODE_DEALLOC;
	msg.msg.cred_id = cursec->csid;
	msg.inode.sb_uuid = sbs->uuid;
	msg.inode.ino = inode->i_ino;

	write_to_relay(&msg, sizeof(msg));
}

/*
 * Accessing an inode - called at file open and useful for directory reads which
 * pass provenance from the metadata stored in the directory inode itself.
 */
static int hifi_inode_permission(struct inode *inode, int mask)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_inode_p msg;

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	/* Prevent processes other than the handler from messing with the log */
	if (inode == relay_dentry->d_inode)
		return -EPERM;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_INODE_P;
	msg.msg.cred_id = cursec->csid;

	if (inode) {
		sbs = inode->i_sb->s_security;
		msg.inode.sb_uuid = sbs->uuid;
		msg.inode.ino = inode->i_ino;
	} else {
		msg.inode.sb_uuid = NULL_UUID_BE;
		msg.inode.ino = 0;
	}

	msg.mask = mask;
	write_to_relay(&msg, sizeof(msg));
	return 0;
}

/*
 * Adding a new filename for an inode
 */
static int hifi_inode_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_link *msg;
	int len = new_dentry->d_name.len;

	msg = kmalloc(sizeof(*msg) + len, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg_initlen(&msg->msg, sizeof(*msg) + len);
	msg->msg.type = PROVMSG_LINK;
	msg->msg.cred_id = cursec->csid;

	sbs = old_dentry->d_sb->s_security;
	msg->inode.sb_uuid = sbs->uuid;
	msg->inode.ino = old_dentry->d_inode->i_ino;
	msg->dir = dir->i_ino;
	memcpy(msg->fname, new_dentry->d_name.name, len);

	write_to_relay(msg, sizeof(*msg) + len);
	kfree(msg);
	return 0;
}

/*
 * Removing a filename for an inode
 */
static int hifi_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_unlink *msg;
	int len = dentry->d_name.len;

	msg = kmalloc(sizeof(*msg) + len, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg_initlen(&msg->msg, sizeof(*msg) + len);
	msg->msg.type = PROVMSG_UNLINK;
	msg->msg.cred_id = cursec->csid;

	sbs = dir->i_sb->s_security;
	msg->dir.sb_uuid = sbs->uuid;
	msg->dir.ino = dir->i_ino;
	memcpy(msg->fname, dentry->d_name.name, len);

	write_to_relay(msg, sizeof(*msg) + len);
	kfree(msg);
	return 0;
}

/*
 * Changing a filename for an inode
 */
static int hifi_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs = old_dentry->d_sb->s_security;
	struct provmsg_link *linkmsg;
	struct provmsg_unlink *unlinkmsg;
	int oldlen = old_dentry->d_name.len;
	int newlen = new_dentry->d_name.len;

	linkmsg = kmalloc(sizeof(*linkmsg) + newlen, GFP_KERNEL);
	if (!linkmsg)
		return -ENOMEM;
	unlinkmsg = kmalloc(sizeof(*unlinkmsg) + oldlen, GFP_KERNEL);
	if (!unlinkmsg) {
		kfree(linkmsg);
		return -ENOMEM;
	}

	msg_initlen(&linkmsg->msg, sizeof(*linkmsg) + newlen);
	linkmsg->msg.type = PROVMSG_LINK;
	linkmsg->msg.cred_id = cursec->csid;
	linkmsg->inode.sb_uuid = sbs->uuid;
	linkmsg->inode.ino = old_dentry->d_inode->i_ino;
	linkmsg->dir = new_dir->i_ino;
	memcpy(linkmsg->fname, new_dentry->d_name.name, newlen);

	msg_initlen(&unlinkmsg->msg, sizeof(*unlinkmsg) + oldlen);
	unlinkmsg->msg.type = PROVMSG_UNLINK;
	unlinkmsg->msg.cred_id = cursec->csid;
	unlinkmsg->dir.sb_uuid = sbs->uuid;
	unlinkmsg->dir.ino = old_dir->i_ino;
	memcpy(unlinkmsg->fname, old_dentry->d_name.name, oldlen);

	// XXX Allocate together and write as a unit
	write_to_relay(linkmsg, sizeof(*linkmsg) + newlen);
	write_to_relay(unlinkmsg, sizeof(*unlinkmsg) + oldlen);
	kfree(unlinkmsg);
	kfree(linkmsg);
	return 0;
}

/*
 * Changing inode attributes - specifically, we're tracking owner, group, and
 * mode.
 */
int hifi_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs = dentry->d_sb->s_security;
	const struct inode *i = dentry->d_inode;
	struct provmsg_setattr msg;

	if ((attr->ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID)) == 0)
		return 0;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SETATTR;
	msg.msg.cred_id = cursec->csid;
	msg.inode.sb_uuid = sbs->uuid;
	msg.inode.ino = i->i_ino;
	msg.uid = (attr->ia_valid & ATTR_UID) ? attr->ia_uid : i->i_uid;
	msg.gid = (attr->ia_valid & ATTR_GID) ? attr->ia_gid : i->i_gid;
	msg.mode = (attr->ia_valid & ATTR_MODE) ? attr->ia_mode : i->i_mode;

	write_to_relay(&msg, sizeof(msg));

	return 0;
}

/*
 * Reading a symbolic link
 */
static int hifi_inode_readlink(struct dentry *dentry)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs = dentry->d_sb->s_security;
	struct provmsg_readlink msg;

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_READLINK;
	msg.msg.cred_id = cursec->csid;
	msg.inode.sb_uuid = sbs->uuid;
	msg.inode.ino = dentry->d_inode->i_ino;

	write_to_relay(&msg, sizeof(msg));
	return 0;
}

/*
 * Reading or writing an open file.  The only calls to this function have @mask
 * set to either MAY_READ or MAY_WRITE, nothing else, and never both.
 */
static int hifi_file_permission(struct file *file, int mask)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_file_p msg;

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_FILE_P;
	msg.msg.cred_id = cursec->csid;

	if (file && file->f_dentry && file->f_dentry->d_inode) {
		sbs = file->f_dentry->d_sb->s_security;
		msg.inode.sb_uuid = sbs->uuid;
		msg.inode.ino = file->f_dentry->d_inode->i_ino;
	} else {
		msg.inode.sb_uuid = NULL_UUID_BE;
		msg.inode.ino = 0;
	}

	msg.mask = mask;
	write_to_relay(&msg, sizeof(msg));
	return 0;
}

/*
 * Mapping an open file into a process's address space.  XXX I'm not sure what
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

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_MMAP;
	msg.msg.cred_id = cursec->csid;

	if (file && file->f_dentry && file->f_dentry->d_inode) {
		sbs = file->f_dentry->d_sb->s_security;
		msg.inode.sb_uuid = sbs->uuid;
		msg.inode.ino = file->f_dentry->d_inode->i_ino;
	} else {
		msg.inode.sb_uuid = NULL_UUID_BE;
		msg.inode.ino = 0;
	}

	msg.prot = prot;
	msg.flags = flags;
	write_to_relay(&msg, sizeof(msg));
	return 0;
}


/******************************************************************************
 *
 * XSI IPC hooks
 *
 ******************************************************************************/

/*
 * Attaching to XSI shared memory
 */
static int hifi_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr,
		int shmflg)
{
	const struct cred_security *cursec = current_security();
	const struct shm_security *shmsec = shp->shm_perm.security;
	struct provmsg_shmat msg;

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SHMAT;
	msg.msg.cred_id = cursec->csid;
	msg.shmid = shmsec->shmid;
	msg.flags = shmflg;

	write_to_relay(&msg, sizeof(msg));
	return 0;
}


/*
 * Sending a message to an XSI message queue
 */
static int hifi_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg,
		int msqflg) {
	const struct cred_security *cursec = current_security();
	const struct msg_security *msgsec = msg->security;
	struct provmsg_mqsend logmsg;

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	msg_initlen(&logmsg.msg, sizeof(logmsg));
	logmsg.msg.type = PROVMSG_MQSEND;
	logmsg.msg.cred_id = cursec->csid;
	logmsg.msgid = msgsec->msgid;

	write_to_relay(&logmsg, sizeof(logmsg));
	return 0;
}

/*
 * Receiving a message from an XSI message queue
 */
static int hifi_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
		struct task_struct *target, long type, int mode) {
	const struct cred_security *cursec = target->cred->security;
	const struct msg_security *msgsec = msg->security;
	struct provmsg_mqrecv logmsg;

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	msg_initlen(&logmsg.msg, sizeof(logmsg));
	logmsg.msg.type = PROVMSG_MQRECV;
	logmsg.msg.cred_id = cursec->csid;
	logmsg.msgid = msgsec->msgid;

	write_to_relay(&logmsg, sizeof(logmsg));
	return 0;
}


/******************************************************************************
 *
 * PROTOCOL-SPECIFIC SOCKET HANDLERS
 *
 ******************************************************************************/

/*
 * Sending on a UNIX domain socket
 */
static int send_unix_msg(struct sock *peersk)
{
	const struct cred_security *cursec = current_security();
	const struct sock_security *psec = peersk->sk_security;
	struct provmsg_socksend msg;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SOCKSEND;
	msg.msg.cred_id = cursec->csid;
	msg.peer = psec->short_id;

	write_to_relay(&msg, sizeof(msg));
	return 0;
}

/*
 * Receiving on a UNIX domain socket (any kind)
 */
static void recv_unix_msg(struct sock *sk)
{
	const struct cred_security *cursec = current_security();
	const struct sock_security *sks = sk->sk_security;
	struct provmsg_sockrecv msg;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SOCKRECV;
	msg.msg.cred_id = cursec->csid;
	msg.sock.host = boot_uuid;
	msg.sock.sock = sks->short_id;

	write_to_relay(&msg, sizeof(msg));
}

/*
 * Sending on a TCP socket
 */
static int send_tcp_msg(struct socket *sock)
{
	const struct cred_security *cursec = current_security();
	const struct sock_security *sks = sock->sk->sk_security;
	struct provmsg_socksend msg;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SOCKSEND;
	msg.msg.cred_id = cursec->csid;
	msg.peer = sks->short_id;

	write_to_relay(&msg, sizeof(msg));
	return 0;
}

/*
 * Receiving on a TCP socket
 */
static void recv_tcp_msg(struct socket *sock)
{
	const struct cred_security *cursec = current_security();
	const struct sock_security *sks = sock->sk->sk_security;
	struct provmsg_sockrecv msg;

	if (!sks->full_set)
		return;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SOCKRECV;
	msg.msg.cred_id = cursec->csid;
	msg.sock = sks->full_id;

	write_to_relay(&msg, sizeof(msg));
}

/*
 * Sending on a UDP socket
 */
static int send_udp_msg(struct sk_buff *skb)
{
	const struct cred_security *cursec = current_security();
	struct skb_security *sks = skb_shinfo(skb)->security;
	struct provmsg_socksend msg;

	if (!sks->set) {
		next_sockid(&sks->id.sock);
		sks->set = 1;
	}

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SOCKSEND;
	msg.msg.cred_id = cursec->csid;
	msg.peer = sks->id.sock;

	write_to_relay(&msg, sizeof(msg));
	return 0;
}

/*
 * Receiving on a UDP socket
 */
static int recv_udp_msg(struct sk_buff *skb)
{
	const struct cred_security *cursec = current_security();
	struct skb_security *sks = skb_shinfo(skb)->security;
	struct provmsg_sockrecv msg;

	if (!sks->set)
		return 0;

	msg_initlen(&msg.msg, sizeof(msg));
	msg.msg.type = PROVMSG_SOCKRECV;
	msg.msg.cred_id = cursec->csid;
	msg.sock = sks->id;

	write_to_relay(&msg, sizeof(msg));
	return 0;
}


/******************************************************************************
 *
 * SOCKET HOOKS
 *
 ******************************************************************************/

/*
 * Sending on a socket
 */
static int hifi_socket_sendmsg(struct socket *sock, struct msghdr *msg,
		int size)
{
	const struct cred_security *cursec = current_security();
	struct cmsghdr *cmsg;
	struct sock *peer;

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
		if (cmsg->cmsg_level == SOL_IP &&
				cmsg->cmsg_type == IP_RETOPTS) {
			printk(KERN_WARNING "Hi-Fi: %s send with IP_RETOPTS\n",
					current->comm);
			return -EPERM;
		}

	switch (sock->sk->sk_family) {
	case AF_UNIX:
		/* Non-stream sockets are better handled by unix_may_send */
		if (sock->sk->sk_type != SOCK_STREAM)
			break;
		peer = unix_sk(sock->sk)->peer;
		/* Not connected.  Send will fail with ENOTCONN. */
		if (!peer)
			break;
		return send_unix_msg(peer);
	case AF_INET:
		/* XXX just TCP for now, UDP handled by append_data */
		if (sock->sk->sk_protocol != IPPROTO_TCP)
			break;
		return send_tcp_msg(sock);
	}
	return 0;
}

/*
 * Appending data to an outgoing datagram
 */
static int hifi_socket_dgram_append(struct sock *sk, struct sk_buff *head)
{
	const struct cred_security *cursec = current_security();

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	/* XXX Just UDP, def. not stream sockets */
	if (sk->sk_family != AF_INET || sk->sk_protocol != IPPROTO_UDP)
		return 0;
	return send_udp_msg(head);
}

/*
 * Receiving on a socket
 */
static void hifi_socket_post_recvmsg(struct socket *sock, struct msghdr *msg,
		int size, int flags)
{
	const struct cred_security *cursec = current_security();

	if (cursec->flags & CSEC_OPAQUE)
		return;

	// XXX more later?
	switch (sock->sk->sk_family) {
	case AF_UNIX:
		recv_unix_msg(sock->sk);
		break;
	case AF_INET:
		if (sock->sk->sk_protocol != IPPROTO_TCP)
			return;
		recv_tcp_msg(sock);
		break;
	}
}

/*
 * Receiving a UDP datagram
 */
static void hifi_socket_dgram_post_recv(struct sock *sk, struct sk_buff *skb)
{
	const struct cred_security *cursec = current_security();

	if (cursec->flags & CSEC_OPAQUE)
		return;
	/* XXX Just UDP for now; other protos might need hook placements */
	if (sk->sk_family != AF_INET || sk->sk_protocol != IPPROTO_UDP)
		return;

	recv_udp_msg(skb);
}

/*
 * Delivering a packet to a socket
 */
static int hifi_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct sock_security *sks = sk->sk_security;
	struct skb_security *sbs = skb_shinfo(skb)->security;

	/* XXX Only TCP */
	if (sk->sk_family != AF_INET || sk->sk_protocol != IPPROTO_TCP)
		return 0;
	if (sks->full_set || !sbs->set)
		return 0;

	sks->full_id = sbs->id;
	sks->full_set = 1;
	return 0;
}

/*
 * Sending datagrams on a UNIX domain socket (closer hook than sendmsg)
 */
static int hifi_unix_may_send(struct socket *sock, struct socket *other)
{
	const struct cred_security *cursec = current_security();

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	/* This should only be called by DGRAM/SEQPACKET sockets */
	BUG_ON(sock->sk->sk_type == SOCK_STREAM);
	return send_unix_msg(other->sk);
}

/*
 * Completing a connection at the client side of a TCP socket
 */
static void hifi_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
	struct sock_security *sec = sk->sk_security;

	/* Discard the ID we got from the listening socket */
	sec->full_set = 0;
}


/******************************************************************************
 *
 * PERMISSION HOOKS
 *
 ******************************************************************************/

/*
 * Feign ignorance to prevent options from being overwritten
 */
static int hifi_socket_setsockopt(struct socket *sock, int level, int optname)
{
	if (sock->sk->sk_family == AF_INET && level == SOL_IP &&
			optname == IP_OPTIONS) {
		printk(KERN_WARNING "Hi-Fi: %s setting IP options via setsockopt\n",
				current->comm);
		return -ENOPROTOOPT;
	}
	return 0;
}

/*
 * Feign ignorance to make OpenSSH work again
 */
static int hifi_socket_getsockopt(struct socket *sock, int level, int optname)
{
	if (sock->sk->sk_family == AF_INET && level == SOL_IP &&
			optname == IP_OPTIONS)
		return -ENOPROTOOPT;
	return 0;
}


/******************************************************************************
 *
 * NETFILTER HANDLERS/HOOKS
 *
 ******************************************************************************/

/*
 * TCP/UDP packet arrival
 */
static int tcp_udp_in(struct sk_buff *skb)
{
	struct skb_security *sec = skb_shinfo(skb)->security;
	BUG_ON(!sec);
	if (detach_packet_label(skb, &sec->id))
		return 0;
	sec->set = 1;
	return 0;
}

/*
 * TCP packet transmission
 */
static int tcp_out(struct sk_buff *skb)
{
	struct sock_security *sec = skb->sk->sk_security;
	if (!sec->short_set) {
		printk(KERN_WARNING "Hi-Fi: short_id not set!\n");
		return 0;
	}
	return label_packet(skb, &sec->short_id);
}

/*
 * UDP packet transmission
 */
static int udp_out(struct sk_buff *skb)
{
	struct skb_security *sec = skb_shinfo(skb)->security;
	if (!sec->set) {
		printk(KERN_WARNING "Hi-Fi: skb id not set!\n");
		return 0;
	}
	return label_packet(skb, &sec->id.sock);
}


/*
 * IPv4 packet arrival - handle by protocol
 */
static unsigned int hifi_ipv4_in(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);

	switch (iph->protocol) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		if (tcp_udp_in(skb))
			return NF_DROP;
		break;
	}

	return NF_ACCEPT;
}

/*
 * IPv4 packet transmission - handle by protocol
 */
static unsigned int hifi_ipv4_out(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;

	iph = ip_hdr(skb);
	switch (iph->protocol) {
	case IPPROTO_UDP:
		if (udp_out(skb))
			return NF_DROP;
		break;
	case IPPROTO_TCP:
		if (tcp_out(skb))
			return NF_DROP;
		break;
	}

	return NF_ACCEPT;
}

/*
 * Initializes the Netfilter hooks
 */
static int __init hifi_nf_init(void)
{
	static struct nf_hook_ops hifi_ipv4_hooks[] = {
		{
			.hook = hifi_ipv4_in,
			.pf = PF_INET,
			.hooknum = NF_INET_LOCAL_IN,
			.priority = NF_IP_PRI_FIRST,
		},
		{
			.hook = hifi_ipv4_out,
			.pf = PF_INET,
			.hooknum = NF_INET_LOCAL_OUT,
			.priority = NF_IP_PRI_LAST,
		},
	};

	if (nf_register_hooks(hifi_ipv4_hooks, ARRAY_SIZE(hifi_ipv4_hooks)))
		panic("Hi-Fi: failed to register netfilter hooks");
	return 0;
}
postcore_initcall(hifi_nf_init);


/******************************************************************************
 *
 * ALLOCATION HOOKS
 *
 ******************************************************************************/

/*
 * Superblock (filesystem) allocation hooks
 */
static int hifi_sb_alloc_security(struct super_block *sb)
{
	struct sb_security *sbs;

	sbs = kzalloc(sizeof(*sbs), GFP_KERNEL);
	if (!sbs)
		return -ENOMEM;

	sb->s_security = sbs;
	return 0;
}

static void hifi_sb_free_security(struct super_block *sb)
{
	struct sb_security *sbs = sb->s_security;

	sb->s_security = NULL;
	kfree(sbs);
}


/*
 * XSI IPC
 */
static int hifi_shm_alloc_security(struct shmid_kernel *shp)
{
	struct shm_security *shmsec;

	shmsec = kzalloc(sizeof(*shmsec), GFP_KERNEL);
	if (!shmsec)
		return -ENOMEM;
	shmsec->shmid = alloc_provid();
	shp->shm_perm.security = shmsec;
	return 0;
}

static void hifi_shm_free_security(struct shmid_kernel *shp)
{
	struct shm_security *shmsec = shp->shm_perm.security;
	int id = shmsec->shmid;

	shp->shm_perm.security = NULL;
	kfree(shmsec);
	free_provid(id);
}

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


/*
 * Socket allocation hooks
 */
static int hifi_socket_post_create(struct socket *sock, int family, int type,
		int protocol, int kern)
{
	struct inet_sock *inet;
	struct ip_options_rcu *old, *opt;

	/* Gotta fit in 320 bits */
	BUILD_BUG_ON(sizeof(struct sockid_opt) > MAX_IPOPTLEN);

	if (family != AF_INET)
		return 0;

	opt = kzalloc(sizeof(*opt) + sizeof(struct sockid_opt), GFP_KERNEL);
	if (!opt)
		return -ENOMEM;
	opt->opt.__data[0] = IPOPT_HIFI;
	opt->opt.__data[1] = sizeof(struct sockid_opt);
	opt->opt.optlen = sizeof(struct sockid_opt);

	inet = inet_sk(sock->sk);
	old = rcu_dereference(inet->inet_opt);
	rcu_assign_pointer(inet->inet_opt, opt);
	if (old) {
		printk(KERN_WARNING "Hi-Fi: inet_opt was already set??\n");
		kfree_rcu(old, rcu);
	}
	return 0;
}

/*
 * Create the temporary request_sock from which the eventual accepted socket
 * will be cloned.  We have the only reference to @req at this point, so we can
 * play fast and loose with RCU.
 */
static int hifi_inet_conn_request(struct sock *sk, struct sk_buff *skb,
		struct request_sock *req)
{
	struct inet_request_sock *irsk = inet_rsk(req);
	struct ip_options_rcu *opt;

	if (sk->sk_family != AF_INET)
		return 0;

	/* XXX Just blow away existing options for now */
	if (irsk->opt)
		kfree(irsk->opt);

	opt = kzalloc(sizeof(*opt) + sizeof(struct sockid_opt), GFP_ATOMIC);
	if (!opt)
		return -ENOMEM;
	opt->opt.__data[0] = IPOPT_HIFI;
	opt->opt.__data[1] = sizeof(struct sockid_opt);
	opt->opt.optlen = sizeof(struct sockid_opt);
	irsk->opt = opt;
	return 0;
}

static int hifi_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	struct sock_security *sec;

	sec = kmalloc(sizeof(*sec), priority);
	if (!sec)
		return -ENOMEM;

	/*
	 * For UNIX sockets, this will become the local ID.  For TCP sockets, it
	 * will be the remote ID.  For UDP sockets, it will be unused.
	 */
	next_sockid(&sec->short_id);
	sec->short_set = 1;
	sec->full_set = 0;
	sk->sk_security = sec;
	return 0;
}

static void hifi_sk_free_security(struct sock *sk)
{
	if (!sk->sk_security)
		return;
	kfree(sk->sk_security);
	sk->sk_security = NULL;
}


/*
 * Socket buffer allocation hooks
 */
static int hifi_skb_shinfo_alloc_security(struct sk_buff *skb, int recycling,
		gfp_t gfp)
{
	struct skb_security *sec;

	if (recycling)
		return 0;

	sec = kmalloc(sizeof(*sec), gfp);
	if (!sec)
		return -ENOMEM;

	sec->set = 0;
	skb_shinfo(skb)->security = sec;
	return 0;
}

static void hifi_skb_shinfo_free_security(struct sk_buff *skb, int recycling)
{
	struct skb_security *sec = skb_shinfo(skb)->security;

	BUG_ON(!sec);

	if (recycling) {
		sec->set = 0;
		return;
	}

	kfree(sec);
	skb_shinfo(skb)->security = NULL;
}

static int hifi_skb_shinfo_copy(struct sk_buff *skb,
		struct skb_shared_info *shinfo, gfp_t gfp)
{
	struct skb_security *oldsec = skb_shinfo(skb)->security;
	struct skb_security *sec;

	sec = kmalloc(sizeof(*sec), gfp);
	if (!sec)
		return -ENOMEM;
	*sec = *oldsec;
	shinfo->security = sec;
	return 0;
}


/******************************************************************************
 *
 * LSM INITIALIZATION
 *
 ******************************************************************************/

/*
 * Sets up the provid bitmap
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
 * Fills out the initial kernel credential structure
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

static struct security_operations hifi_security_ops = {
	.name    = "hifi",

	/* Provenance-generating hooks */
#define HANDLE(HOOK) .HOOK = hifi_##HOOK

	HANDLE(cred_prepare),
	HANDLE(cred_alloc_blank),
	HANDLE(cred_free),
	HANDLE(cred_transfer),
	HANDLE(task_fix_setuid),

	HANDLE(bprm_check_security),
	HANDLE(bprm_committing_creds),

	HANDLE(sb_kern_mount),

	HANDLE(inode_init_security),
	HANDLE(inode_free_security),
	HANDLE(inode_permission),
	HANDLE(inode_link),
	HANDLE(inode_unlink),
	HANDLE(inode_rename),
	HANDLE(inode_setattr),
	HANDLE(inode_readlink),

	HANDLE(file_permission),
	HANDLE(file_mmap),

	HANDLE(shm_shmat),
	HANDLE(msg_queue_msgsnd),
	HANDLE(msg_queue_msgrcv),

	HANDLE(socket_sendmsg),
	HANDLE(socket_post_recvmsg),
	HANDLE(socket_dgram_append),
	HANDLE(socket_dgram_post_recv),
	HANDLE(socket_sock_rcv_skb),
	HANDLE(unix_may_send),
	HANDLE(inet_conn_established),

	/* Permisison hooks */

	HANDLE(socket_setsockopt),
	HANDLE(socket_getsockopt),

	/* Allocation hooks */

	HANDLE(sb_alloc_security),
	HANDLE(sb_free_security),

	HANDLE(shm_alloc_security),
	HANDLE(shm_free_security),
	HANDLE(msg_msg_alloc_security),
	HANDLE(msg_msg_free_security),

	HANDLE(socket_post_create),
	HANDLE(inet_conn_request),
	HANDLE(sk_alloc_security),
	HANDLE(sk_free_security),
	HANDLE(skb_shinfo_alloc_security),
	HANDLE(skb_shinfo_free_security),
	HANDLE(skb_shinfo_copy),
};

static int __init hifi_init(void)
{
	int rv = 0;

	if (!security_module_enable(&hifi_security_ops)) {
		printk(KERN_ERR "Hi-Fi: ERROR - failed to enable module\n");
		return -EINVAL;
	}
	printk(KERN_INFO "Hi-Fi: module enabled\n");

	boot_buffer = kmalloc(boot_buf_size, GFP_KERNEL);
	rv = init_provid_map();
	if (rv)
		return rv;
	if (set_init_creds())
		panic("Hi-Fi: Failed to allocate creds for initial task.");
	/* Generate a random boot UUID */
	generate_random_uuid(boot_uuid.b);

	/* Finally register */
	if (register_security(&hifi_security_ops))
		panic("Hi-Fi: failed to register operations");

	printk(KERN_INFO "Hi-Fi: registered\n");
	return 0;
}
security_initcall(hifi_init);
