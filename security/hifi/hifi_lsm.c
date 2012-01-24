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

static int relay_subbuf_start(struct rchan_buf *buf, void *subbuf,
		void *prev_subbuf, size_t prev_padding)
{
	// Prevent loss of provenance data
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
static const struct provmsg_boot init_bootmsg = {
	.header.msgtype = PROVMSG_BOOT,
	.header.cred_id = 0,
	.version = HIFI_PROTO_VERSION,
};

static const struct provmsg_setid init_setidmsg = {
	.header.msgtype = PROVMSG_SETID,
	.header.cred_id = 0,
	/* Static, so all IDs are (correctly) inited to 0 */
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
	// XXX copy host uuid here
}

/*
 * Reads the label off of the packet in skb.
 */
static int get_packet_label(const struct sk_buff *skb, struct sockid *label)
{
	struct iphdr *iph = ip_hdr(skb);
	u8 *p, *end;

	p = (u8 *)(iph + 1);
	end = p + ((iph->ihl - 5) << 2);
	while (p < end)
		switch (*p) {
			case IPOPT_HIFI:
				memcpy(label, p + 2, sizeof(*label));
				return 0;
			case IPOPT_END:
				return -1;
			case IPOPT_NOOP:
				p++;
				continue;
			default:
				p += *(p + 1);
				continue;
		}
	return -1;
}

/*
 * Adds a label to the packet in skb.
 */
static int label_packet(struct sk_buff *skb, const struct sockid *label)
{
	struct iphdr *iph;
	struct ip_options *opt;
	int len_delta, rv;
	struct sockid_opt *ipopt;

	/* Gotta fit in 320 bits */
	BUILD_BUG_ON(sizeof(*ipopt) > MAX_IPOPTLEN);

	/* Update in-core options structure */
	opt = &IPCB(skb)->opt;
	if (opt->optlen + sizeof(*ipopt) <= MAX_IPOPTLEN) {
		/* Option will fit in the header */
		len_delta = sizeof(*ipopt);
		opt->optlen += sizeof(*ipopt);
	} else {
		/* Option won't fit - erase the others */
		printk(KERN_WARNING "Hi-Fi: erasing packet options!\n");
		len_delta = sizeof(*ipopt) - opt->optlen;
		if (opt->optlen > 0)
			memset(opt, 0, sizeof(*opt));
		opt->optlen = sizeof(*ipopt);
	}

	/* Update the packet itself */
	rv = skb_cow(skb, skb_headroom(skb) + len_delta);
	if (rv < 0)
		return rv;
	iph = ip_hdr(skb);
	if (len_delta > 0) {
		/* Expanding case */
		skb_push(skb, len_delta);

		memmove((char *)iph - len_delta, iph, sizeof(*iph));
		skb_reset_network_header(skb);
		iph = ip_hdr(skb);

		iph->ihl = 5 + (opt->optlen >> 2);
		iph->tot_len = htons(skb->len);
	}

	ipopt = (struct sockid_opt *)(iph + 1);
	ipopt->num = IPOPT_HIFI;
	ipopt->len = sizeof(ipopt);
	ipopt->label = *label;

	if (len_delta < 0) {
		/* Nopping case */
		opt->optlen += -len_delta;
		memset(ipopt + 1, IPOPT_NOP, -len_delta);
	}

	/* Um, yeah, stuff changed */
	opt->is_changed = 1;
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

	buf.header.msgtype = PROVMSG_CREDFORK;
	buf.header.cred_id = old->csid;
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
	buf.header.msgtype = PROVMSG_CREDFREE;
	buf.header.cred_id = id;
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
 * Committing (and possibly changing) credentials at process execution
 */
static void hifi_bprm_committing_creds(struct linux_binprm *bprm)
{
	const struct cred_security *csec = bprm->cred->security;
	struct provmsg_setid buf;

	if (csec->flags & CSEC_OPAQUE)
		return;

	buf.header.msgtype = PROVMSG_SETID;
	buf.header.cred_id = csec->csid;
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
		generate_random_uuid(sbs->uuid);
		goto out;
	}

	mutex_lock(&i_root->i_mutex);
	rv = i_root->i_op->getxattr(d_root, XATTR_NAME_HIFI, sbs->uuid, 16);
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

/*
 * Deleting an inode (when nlink hits 0)
 */
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
 * Adding a new filename for an inode
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

/*
 * Removing a filename for an inode
 */
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

/*
 * Changing a filename for an inode
 */
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
 * Changing inode attributes - specifically, we're tracking owner, group, and
 * mode.
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
 * Reading a symbolic link
 */
static int hifi_inode_readlink(struct dentry *dentry)
{
	const struct cred_security *cursec = current_security();
	const struct sb_security *sbs;
	struct provmsg_readlink *msg;

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	msg = kmalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg->header.msgtype = PROVMSG_READLINK;
	msg->header.cred_id = cursec->csid;

	sbs = dentry->d_sb->s_security;
	memcpy(msg->inode.sb_uuid, sbs->uuid, sizeof(msg->inode.sb_uuid));
	msg->inode.ino = dentry->d_inode->i_ino;

	write_to_relay(msg, sizeof(*msg));
	kfree(msg);
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

	msg.header.msgtype = PROVMSG_SHMAT;
	msg.header.cred_id = cursec->csid;
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

	logmsg.header.msgtype = PROVMSG_MQSEND;
	logmsg.header.cred_id = cursec->csid;
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

	logmsg.header.msgtype = PROVMSG_MQRECV;
	logmsg.header.cred_id = cursec->csid;
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
 * Sending on a datagram UNIX domain socket
 */
static int send_unix_dgram(struct socket *sock, struct socket *other)
{
	const struct cred_security *cursec = current_security();
	struct sb_security *sbs;
	struct provmsg_unixsend msg;

	/* Only use this function for connectionless sockets */
	if (sock->sk->sk_family != AF_UNIX || sock->sk->sk_type != SOCK_DGRAM)
		return 0;

	msg.header.msgtype = PROVMSG_UNIXSEND;
	msg.header.cred_id = cursec->csid;

	sbs = SOCK_INODE(other)->i_sb->s_security;
	memcpy(msg.inode.sb_uuid, sbs->uuid, sizeof(msg.inode.sb_uuid));
	msg.inode.ino = SOCK_INODE(other)->i_ino;

	write_to_relay(&msg, sizeof(msg));
	return 0;
}

/*
 * Sending on a connection-mode UNIX domain socket
 */
static int send_unix_connmode(struct socket *sock, struct msghdr *msg, int size)
{
	const struct cred_security *cursec = current_security();
	struct sock *peer;
	struct socket *peersock;
	struct sb_security *sbs;
	struct provmsg_unixsend logmsg;

	peer = unix_sk(sock->sk)->peer;
	/* Socket is not connected.  Will return with ENOTCONN. */
	if (!peer)
		return 0;

	peersock = peer->sk_socket;
	/* XXX Why does this happen three times in kernel startup, all with
	 * SOCK_SEQPACKET?  It appears that a legitimate message is sent, so we
	 * need to figure out how to either get the peer inode or wait for the
	 * peer to be fully initialized.  Something.
	 */
	if (!peersock) {
		printk(KERN_WARNING "Socket send before peer is inited\n");
		return 0;
	}

	logmsg.header.msgtype = PROVMSG_UNIXSEND;
	logmsg.header.cred_id = cursec->csid;

	sbs = SOCK_INODE(peersock)->i_sb->s_security;
	memcpy(logmsg.inode.sb_uuid, sbs->uuid, sizeof(logmsg.inode.sb_uuid));
	logmsg.inode.ino = SOCK_INODE(peersock)->i_ino;

	write_to_relay(&logmsg, sizeof(logmsg));
	return 0;
}

/*
 * Receiving on a UNIX domain socket (any kind)
 */
static void recv_unix_msg(struct socket *sock, struct msghdr *msg, int size,
		int flags)
{
	const struct cred_security *cursec = current_security();
	struct sb_security *sbs;
	struct provmsg_unixrecv logmsg;

	logmsg.header.msgtype = PROVMSG_UNIXRECV;
	logmsg.header.cred_id = cursec->csid;

	sbs = SOCK_INODE(sock)->i_sb->s_security;
	memcpy(logmsg.inode.sb_uuid, sbs->uuid, sizeof(logmsg.inode.sb_uuid));
	logmsg.inode.ino = SOCK_INODE(sock)->i_ino;

	write_to_relay(&logmsg, sizeof(logmsg));
}

/*
 * Sending on a TCP socket
 */
static int send_tcp_msg(struct socket *sock, struct msghdr *msg, int size)
{
	const struct cred_security *cursec = current_security();
	const struct sock_security *sks = sock->sk->sk_security;

	printk(KERN_INFO "tcp send 0x%x -> %04hx:%08x\n", cursec->csid,
			sks->remote_id.high, sks->remote_id.low);
	return 0;
}

/*
 * Receiving on a TCP socket
 */
static void recv_tcp_msg(struct socket *sock, struct msghdr *msg, int size,
		int flags)
{
	const struct cred_security *cursec = current_security();
	const struct sock_security *sks = sock->sk->sk_security;

	printk(KERN_INFO "tcp recv 0x%x <- %04hx:%08x\n", cursec->csid,
			sks->local_id.high, sks->local_id.low);
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

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	switch (sock->sk->sk_family) {
	case AF_UNIX:
		/* XXX Just connection-mode sockets for now */
		if (sock->sk->sk_type == SOCK_DGRAM)
			break;
		return send_unix_connmode(sock, msg, size);
	case AF_INET:
		// XXX just TCP for now
		if (sock->sk->sk_prot != &tcp_prot)
			break;
		return send_tcp_msg(sock, msg, size);
	}
	return 0;
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
		recv_unix_msg(sock, msg, size, flags);
		break;
	case AF_INET:
		if (sock->sk->sk_prot != &tcp_prot)
			return;
		recv_tcp_msg(sock, msg, size, flags);
		break;
	}
}

/*
 * Delivering a packet to a socket
 */
static int hifi_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct sock_security *sks = sk->sk_security;
	struct skb_security *sbs = skb_shinfo(skb)->security;

	/* XXX Only TCP */
	if (sk->sk_prot != &tcp_prot || sks->local_set || !sbs->set)
		return 0;

	sks->local_set = 1;
	sks->local_id = sbs->id;
	return 0;
}

/*
 * Sending on a UNIX domain socket
 */
static int hifi_unix_may_send(struct socket *sock, struct socket *other)
{
	const struct cred_security *cursec = current_security();

	if (cursec->flags & CSEC_OPAQUE)
		return 0;

	switch (sock->sk->sk_type) {
	case SOCK_DGRAM:
		return send_unix_dgram(sock, other);
		break;
	}
	return 0;
}

/*
 * Completing a connection at the client side of a TCP socket
 */
static void hifi_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
	struct sock_security *sec = sk->sk_security;

	next_sockid(&sec->remote_id);
	sec->remote_set = 1;
	// skb->sk == NULL
	// sk == parent socket
}

/*
 * Completing a connection at the server side of a TCP socket
 */
static void hifi_inet_csk_clone(struct sock *newsk,
		const struct request_sock *req)
{
	struct sock_security *sec = newsk->sk_security;

	next_sockid(&sec->remote_id);
	sec->remote_set = 1;
	// req == same from inet_conn_request
}


/******************************************************************************
 *
 * NETFILTER HANDLERS/HOOKS
 *
 ******************************************************************************/

/*
 * TCP packet arrival
 */
static int tcp_in(struct sk_buff *skb)
{
	struct skb_security *sec = skb_shinfo(skb)->security;

	if (get_packet_label(skb, &sec->id))
		return 0;
	sec->set = 1;
	// skb->sk == NULL
	return 0;
}

/*
 * TCP packet transmission
 */
static int tcp_out(struct sk_buff *skb)
{
	struct sock_security *sec = skb->sk->sk_security;
	if (!sec->remote_set)
		return 0;
	//tcph = (struct tcphdr *) ((char *) iph + (iph->ihl << 2));
	return label_packet(skb, &sec->remote_id);
}


/*
 * UDP packet arrival
 */
static int udp_in(struct sk_buff *skb)
{
	struct skb_security *sec = skb_shinfo(skb)->security;

	if (get_packet_label(skb, &sec->id))
		return 0;
	sec->set = 1;
	// skb->sk == NULL
	printk(KERN_INFO "incoming udp, label=%04hx:%08x\n",
			sec->id.high, sec->id.low);
	return 0;
}

/*
 * UDP packet transmission
 */
static int udp_out(struct sk_buff *skb)
{
	struct sockid label;

	printk(KERN_INFO "outgoing udp\n");
	// XXX not here... at send
	next_sockid(&label);
	return label_packet(skb, &label);
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
		if (udp_in(skb))
			return NF_DROP;
		break;
	case IPPROTO_TCP:
		if (tcp_in(skb))
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
static int hifi_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	struct sock_security *sec;

	sec = kzalloc(sizeof(*sec), priority);
	if (!sec)
		return -ENOMEM;

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

static void hifi_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
	// Is already allocated
	// Called when a new child is cloned from a listening socket
}


/*
 * Socket buffer allocation hooks
 */
static int hifi_skb_shinfo_alloc_security(struct sk_buff *skb, int recycling,
		gfp_t gfp)
{
	struct skb_security *sec;

	if (recycling) {
		memset(skb_shinfo(skb)->security, 0, sizeof(*sec));
		return 0;
	}

	sec = kzalloc(sizeof(*sec), gfp);
	if (!sec)
		return -ENOMEM;

	skb_shinfo(skb)->security = sec;
	return 0;
}

static void hifi_skb_shinfo_free_security(struct sk_buff *skb, int recycling)
{
	if (recycling)
		return;

	if (skb_shinfo(skb)->security) {
		kfree(skb_shinfo(skb)->security);
		skb_shinfo(skb)->security = NULL;
	}
}

static int hifi_skb_shinfo_copy(struct sk_buff *skb,
		struct skb_shared_info *shinfo, gfp_t gfp)
{
	struct skb_security *sec;

	sec = kmalloc(sizeof(*sec), gfp);
	if (!sec)
		return -ENOMEM;
	memcpy(sec, skb_shinfo(skb)->security, sizeof(*sec));
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
	HANDLE(socket_sock_rcv_skb),
	HANDLE(unix_may_send),
	HANDLE(inet_conn_established),
	HANDLE(inet_csk_clone),

	/* Allocation hooks */

	HANDLE(sb_alloc_security),
	HANDLE(sb_free_security),

	HANDLE(shm_alloc_security),
	HANDLE(shm_free_security),
	HANDLE(msg_msg_alloc_security),
	HANDLE(msg_msg_free_security),

	HANDLE(sk_alloc_security),
	HANDLE(sk_free_security),
	HANDLE(sk_clone_security),
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

	/* Finally register */
	if (register_security(&hifi_security_ops))
		panic("Hi-Fi: failed to register operations");

	printk(KERN_INFO "Hi-Fi: registered\n");
	return 0;
}
security_initcall(hifi_init);
