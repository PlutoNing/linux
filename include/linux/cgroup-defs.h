/* SPDX-License-Identifier: GPL-2.0 */
/*
 * linux/cgroup-defs.h - basic definitions for cgroup
 *
 * This file provides basic type and interface.  Include this file directly
 * only if necessary to avoid cyclic dependencies.
 */
#ifndef _LINUX_CGROUP_DEFS_H
#define _LINUX_CGROUP_DEFS_H

#include <linux/limits.h>
#include <linux/list.h>
#include <linux/idr.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/percpu-refcount.h>
#include <linux/percpu-rwsem.h>
#include <linux/u64_stats_sync.h>
#include <linux/workqueue.h>
#include <linux/bpf-cgroup.h>
#include <linux/psi_types.h>

#ifdef CONFIG_CGROUPS

struct cgroup;
struct cgroup_root;
struct cgroup_subsys;
struct cgroup_taskset;
struct kernfs_node;
struct kernfs_ops;
struct kernfs_open_file;
struct seq_file;
struct poll_table_struct;

#define MAX_CGROUP_TYPE_NAMELEN 32
#define MAX_CGROUP_ROOT_NAMELEN 64
#define MAX_CFTYPE_NAME		64

/* define the enumeration of all cgroup subsystems */
#define SUBSYS(_x) _x ## _cgrp_id,
enum cgroup_subsys_id {
#include <linux/cgroup_subsys.h>
	CGROUP_SUBSYS_COUNT,
};
#undef SUBSYS

/* bits in struct cgroup_subsys_state flags field */
enum {
	CSS_NO_REF	= (1 << 0), /* no reference counting for this css，2024年07月11日15:39:57可否理解为已下线？2024年7月14日13:50:12
	还是不清楚
	2024年07月17日10:59:48
	和root css相关？ */
	CSS_ONLINE	= (1 << 1), /* between ->css_online() and ->css_offline() */
	CSS_RELEASED	= (1 << 2), /* refcnt reached zero, released */
	CSS_VISIBLE	= (1 << 3), /* css is visible to userland，销毁css对应文件夹时置否 */
	CSS_DYING	= (1 << 4), /* css is dying */
};

/* bits in struct cgroup flags field */
enum {
	/* Control Group requires release notifications to userspace */
	CGRP_NOTIFY_ON_RELEASE,
	/*
	 * Clone the parent's configuration when creating a new child
	 * cpuset cgroup.  For historical reasons, this option can be
	 * specified at mount time and thus is implemented here.
	 */
	CGRP_CPUSET_CLONE_CHILDREN,

	/* Control group has to be frozen. */
	CGRP_FREEZE,

	/* Cgroup is frozen. */
	CGRP_FROZEN,
};

/* cgroup_root->flags */
enum {
	CGRP_ROOT_NOPREFIX	= (1 << 1), /* mounted subsystems have no named prefix */
	CGRP_ROOT_XATTR		= (1 << 2), /* supports extended attributes */

	/*
	 * Consider namespaces as delegation boundaries.  If this flag is
	 * set, controller specific interface files in a namespace root
	 * aren't writeable from inside the namespace.
	 */
	CGRP_ROOT_NS_DELEGATE	= (1 << 3),

	/*
	 * Enable cpuset controller in v1 cgroup to use v2 behavior.
	 */
	CGRP_ROOT_CPUSET_V2_MODE = (1 << 4),

	/*
	 * Enable legacy local memory.events.
	 */
	CGRP_ROOT_MEMORY_LOCAL_EVENTS = (1 << 5),
};

/* cftype->flags */
enum {
	CFTYPE_ONLY_ON_ROOT	= (1 << 0),	/* only create on root cgrp */
	CFTYPE_NOT_ON_ROOT	= (1 << 1),	/* don't create on root cgrp */
	CFTYPE_NS_DELEGATABLE	= (1 << 2),	/* writeable beyond delegation boundaries */

	CFTYPE_NO_PREFIX	= (1 << 3),	/* (DON'T USE FOR NEW FILES) no subsys prefix */
	CFTYPE_WORLD_WRITABLE	= (1 << 4),	/* (DON'T USE FOR NEW FILES) S_IWUGO */
	CFTYPE_DEBUG		= (1 << 5),	/* create when cgroup_debug */

	/* internal flags, do not use outside cgroup core proper */
	__CFTYPE_ONLY_ON_DFL	= (1 << 16),	/* only on default hierarchy */
	__CFTYPE_NOT_ON_DFL	= (1 << 17),	/* not on default hierarchy */
};

/*
 * cgroup_file is the handle for a file instance created in a cgroup which
 * is used, for example, to generate file changed notifications.  This can
 * be obtained by setting cftype->file_offset.
 2024年6月21日23:59:09

 */
struct cgroup_file {
	/* do not access any fields from outside cgroup core */
	/* 对应内核fs里的节点 */
	struct kernfs_node *kn;
	unsigned long notified_at;
	struct timer_list notify_timer;
};

/*
2024年06月20日16:45:48
pcb里存储一组指向 cgroup_subsys_state 的指针，通过这个指针进程可以获
取到对应的cgroups信息，
一个 cgroup_subsys_state 就是进程与一个特定子系统相关的信息
 * Per-subsystem/per-cgroup state maintained by the system.  This is the
 * fundamental structural building block that controllers deal with.
 *
 * Fields marked with "PI:" are public and immutable and may be accessed
 * directly without synchronization.
 */
struct cgroup_subsys_state {
	/* PI: the cgroup that this css is attached to 
	cgroup指针指向了一个cgroup结构，也就是进程属于的cgroup。进程受到子系统的控制，实际上是通过
	加入到特定的cgroup实现的，因为cgroup在特定的层级上，而子系统又是附加到层级上的。*/
	struct cgroup *cgroup;

	/* PI: the cgroup subsystem that this css is attached to
	这个css的ss子系统
	 */
	struct cgroup_subsys *ss;

	/* reference count - access via css_[try]get() and css_put()
	引用计数 - 通过 css_[try]get() 和 css_put() 访问 */
	struct percpu_ref refcnt;

	/* siblings list anchored at the parent's ->children */
	/* 锚定在 parent->children 的兄弟列表 */
	struct list_head sibling;
	/* 2024年07月09日18:51:13
	css的孩子链表 */
	struct list_head children;

	/* flush target list anchored at cgrp->rstat_css_list 
	刷新锚定在 cgrp->rstat_css_list 上的目标列表
	*/
	struct list_head rstat_css_node;

	/*
	 * PI: Subsys-unique ID.  0 is unused and root is always 1.  The
	 * matching css can be looked up using css_from_id().
	 子系统唯一 ID。 0 未使用，root 始终为 1。可以使用 css_from_id() 查找匹配的 css。
	 */
	int id;
/* css的flags */
	unsigned int flags;

	/*
	 * Monotonically increasing unique serial number which defines a
	 * uniform order among all csses.  It's guaranteed that all
	 * ->children lists are in the ascending order of ->serial_nr and
	 * used to allow interrupting and resuming iterations.
	 单调递增的唯一序列号，它定义了所有 css 之间的统一顺序。保证所有 ->children 
	 列表都按 ->serial_nr 的升序排列，并用于允许打断和resume遍历。
	 init_and_link_css()中初始化为 css_serial_nr_next++
	 */
	u64 serial_nr;

	/*
	 * Incremented by online self and children.  Used to guarantee that
	 * parents are not offlined before their children.
	 由online的自己和孩子增加。用于保证parent不在孩子之前offline。
	 */
	atomic_t online_cnt;

	/* percpu_ref killing and RCU release 
	 percpu_ref killing 和 RCU 释放。*/
	struct work_struct destroy_work;

	struct rcu_work destroy_rwork;

	/*
	 * PI: the parent css.	Placed here for cache proximity to following
	 * fields of the containing structure.
	 父CSS
	 */
	struct cgroup_subsys_state *parent;
};

/*
 * A css_set is a structure holding pointers to a set of
 * cgroup_subsys_state objects. This saves space in the task struct
 * object and speeds up fork()/exit(), since a single inc/dec and a
 * list_add()/del() can bump the reference count on the entire cgroup
 * set for a task.
 2024年06月20日16:53:36
 每个进程对应一个css_set结构，
 css_set存储了与进程相关的cgropus信息
 css_set 是一个包含指向一组 cgroup_subsys_state 对象的指针的结构。
 这节省了 task_struct 中的空间并加快了 fork()/exit()，因为单个 inc/dec 
 和 list_add()/del() 可以增加任务的整个 cgroup set 的引用计数。
 */
struct css_set {
	/*
	 * Set of subsystem states, one for each subsystem. This array is
	 * immutable after creation apart from the init_css_set during
	 * subsystem registration (at boot time).
	 一组子系统的状态，每个子系统一个。 除了子系统注册期间（启动时）的 init_css_set 之外，该数组在创建后是不可变的。
	 subsys是一个指针数组，存储一组指向cgroup_subsys_state的指针。一个cgroup_subsys_state
	 就是进程与一个特定的子系统相关的信息。通过这个指针，进程就可以获得相应的cgroups控制信息了。
	 存储一组指向 cgroup_subsys_state 的指针，通过这个指针进程可以获取到对应
	 的cgroups信息，一个 cgroup_subsys_state 就是进程与一个特定子系统相关的信息，
	 cgroup_subsys_state结构体如下：
	 2024年07月10日11:12:00
	 此cset生效的css数组
	 */
	struct cgroup_subsys_state *subsys[CGROUP_SUBSYS_COUNT];

	/* reference count */
	refcount_t refcount;

	/*
	 * For a domain cgroup, the following points to self.  If threaded,
	 * to the matching cset of the nearest domain ancestor.  The
	 * dom_cset provides access to the domain cgroup and its csses to
	 * which domain level resource consumptions should be charged.
	 对于 domain cgroup，以下指向自己. 如果线程化，则到最近域祖先的匹配cset。
	 dom_cset 提供对域 cgroup 及其 csses 的访问，域级资源消耗应计入其中。
	 */
	struct css_set *dom_cset;

	/* the default cgroup associated with this css_set
	与此 css_set 关联的默认 cgroup */
	struct cgroup *dfl_cgrp;

	/* internal task count, protected by css_set_lock 
	内部任务计数，受 css_set_lock 保护*/
	int nr_tasks;

	/*
	 * Lists running through all tasks using this cgroup group.
	 * mg_tasks lists tasks which belong to this cset but are in the
	 * process of being migrated out or in.  Protected by
	 * css_set_rwsem, but, during migration, once tasks are moved to
	 * mg_tasks, it can be read safely while holding cgroup_mutex.
	 */
	 /* tasks是将所有引用此css_set的进程连接成链表 */
	struct list_head tasks;
	/* 列出了属于此 cset 但正在迁移出或迁移入的任务。被 css_set_rwsem 保护，但是，在迁移过程中，
	一旦将任务移动到 mg_tasks，就可以在持有 cgroup_mutex 的同时安全地读取它。 */
	struct list_head mg_tasks;
/* 从cset分离的tsk放在这里，通过cg list放在这 */
	struct list_head dying_tasks;

	/* all css_task_iters currently walking this cset
	当前正在执行此 cset 的所有 css_task_iters */
	struct list_head task_iters;

	/*
	 * On the default hierarhcy, ->subsys[ssid] may point to a css
	 * attached to an ancestor instead of the cgroup this css_set is
	 * associated with.  The following node is anchored at
	 * ->subsys[ssid]->cgroup->e_csets[ssid] and provides a way to
	 * iterate through all css's attached to a given cgroup.
	 在默认层次结构中，->subsys[ssid] 可能指向附加到祖先的 css，而不是与 css_set 关联的 cgroup。 
	 以下节点锚定在 ->subsys[ssid]->cgroup->e_csets[ssid] 并提供了一种方法来遍历所有附加到给定 cgroup 的 css。
	 */
	struct list_head e_cset_node[CGROUP_SUBSYS_COUNT];

	/* all threaded csets whose ->dom_cset points to this cset
	->dom_cset 指向此 cset 的所有线程 cset */
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;

	/*
	 * List running through all cgroup groups in the same hash
	 * slot. Protected by css_set_lockhlist是嵌入的hlist_node，
	 用于把所有的css_set组成一个hash表，这样内核可以快速查找特定的
	 css_set
	 */
	struct hlist_node hlist;

	/*
	 * List of cgrp_cset_links pointing at cgroups referenced from this
	 * css_set.  Protected by css_set_lock.
	 指向从此 css_set 引用的 cgroups 的 cgrp_cset_links 列表。
	 2024年07月10日10:29:38
	 借助cgrp_cset_link作为连接件链接每一个cgroup，
	 */
	struct list_head cgrp_links;

	/*
	 * List of csets participating in the on-going migration either as
	 * source or destination.  Protected by cgroup_mutex.
	 列出作为源或目标，参与正在进行的迁移的 cset 列表
	 */
	struct list_head mg_preload_node;
	/*cset的 mg node连接到 mgctx->tset.src_csets */
	struct list_head mg_node;

	/*
	 * If this cset is acting as the source of migration the following
	 * two fields are set.  mg_src_cgrp and mg_dst_cgrp are
	 * respectively the source and destination cgroups of the on-going
	 * migration.  mg_dst_cset is the destination cset the target tasks
	 * on this cset should be migrated to.  Protected by cgroup_mutex.
	 如果此 cset 充当迁移的源，则设置以下两个字段。mg_src_cgrp 和 mg_dst_cgrp 
	 分别是正在进行的迁移的源 cgroup 和目标 cgroup。mg_dst_cset 是此 cset 上的
	 目标任务应迁移到的目标 cset。受 cgroup_mutex 保护。
	 */
	struct cgroup *mg_src_cgrp;
	struct cgroup *mg_dst_cgrp;
	/*  */
	struct css_set *mg_dst_cset;

	/* 
	是否下线
	dead and being drained, ignore for migration */
	bool dead;

	/* For RCU-protected deletion */
	struct rcu_head rcu_head;
};

struct cgroup_base_stat {
	struct task_cputime cputime;
};

/*
 * rstat - cgroup scalable recursive statistics.  Accounting is done
 * per-cpu in cgroup_rstat_cpu which is then lazily propagated up the
 * hierarchy on reads.
 *
 * When a stat gets updated, the cgroup_rstat_cpu and its ancestors are
 * linked into the updated tree.  On the following read, propagation only
 * considers and consumes the updated tree.  This makes reading O(the
 * number of descendants which have been active since last read) instead of
 * O(the total number of descendants).
 *
 * This is important because there can be a lot of (draining) cgroups which
 * aren't active and stat may be read frequently.  The combination can
 * become very expensive.  By propagating selectively, increasing reading
 * frequency decreases the cost of each read.
 *
 * This struct hosts both the fields which implement the above -
 * updated_children and updated_next - and the fields which track basic
 * resource statistics on top of it - bsync, bstat and last_bstat.
 */
struct cgroup_rstat_cpu {
	/*
	 * ->bsync protects ->bstat.  These are the only fields which get
	 * updated in the hot path.
	 */
	struct u64_stats_sync bsync;
	struct cgroup_base_stat bstat;

	/*
	 * Snapshots at the last reading.  These are used to calculate the
	 * deltas to propagate to the global counters.
	 */
	struct cgroup_base_stat last_bstat;

	/*
	 * Child cgroups with stat updates on this cpu since the last read
	 * are linked on the parent's ->updated_children through
	 * ->updated_next.
	 *
	 * In addition to being more compact, singly-linked list pointing
	 * to the cgroup makes it unnecessary for each per-cpu struct to
	 * point back to the associated cgroup.
	 *
	 * Protected by per-cpu cgroup_rstat_cpu_lock.
	 */
	struct cgroup *updated_children;	/* terminated by self cgroup */
	struct cgroup *updated_next;		/* NULL iff not on the list */
};

struct cgroup_freezer_state {
	/* Should the cgroup and its descendants be frozen. */
	bool freeze;

	/* Should the cgroup actually be frozen? */
	int e_freeze;

	/* Fields below are protected by css_set_lock */

	/* Number of frozen descendant cgroups */
	int nr_frozen_descendants;

	/*
	 * Number of tasks, which are counted as frozen:
	 * frozen, SIGSTOPped, and PTRACEd.
	 */
	int nr_frozen_tasks;
};
/*
2024-06-20 17:02:51
cgroup 指针指向了一个 cgroup 结构，也就是进程属于的 cgroup，进程受到子系统控制就
是加入到特定的cgroup来实现的，就是对应这里的cgroup，由此看出进程和cgroup的关系是多对多关系。*/
struct cgroup {
	/* self css with NULL ->ss, points back to this cgroup
	自己关联的css
	 */
	struct cgroup_subsys_state self;

	unsigned long flags;		/* "unsigned long" so bitops work */

	/*
	 * idr allocated in-hierarchy ID.
	 *
	 * ID 0 is not used, the ID of the root cgroup is always 1, and a
	 * new cgroup will be assigned with a smallest available ID.
	 *
	 * Allocating/Removing ID must be protected by cgroup_mutex.
	 */
	int id;

	/*
	 * The depth this cgroup is at.  The root is at depth zero and each
	 * step down the hierarchy increments the level.  This along with
	 * ancestor_ids[] can determine whether a given cgroup is a
	 * descendant of another without traversing the hierarchy.
	 在层级里的深度，root=0
	 层次结构的每一层都会增加深度。这与 ancestor_ids[] 一起可以确定给定
	  cgroup 是否是另一个 cgroup 的后代，而无需遍历层次结构。
	  2024年07月09日20:50:14
	  表示在层级里的深度
	 */
	int level;

	/* Maximum allowed descent tree depth 
	最大允许树深度*/
	int max_depth;

	/*
	 * Keep track of total numbers of visible and dying descent cgroups.
	 * Dying cgroups are cgroups which were deleted by a user,
	 * but are still existing because someone else is holding a reference.
	 * max_descendants is a maximum allowed number of descent cgroups.
	 *
	 * nr_descendants and nr_dying_descendants are protected
	 * by cgroup_mutex and css_set_lock. It's fine to read them holding
	 * any of cgroup_mutex and css_set_lock; for writing both locks
	 * should be held.
	 跟踪可见和dying descent cgroup 的总数。dying cgroups 是被用户删除的 cgroups，
	 但由于其他人持有引用而仍然存在。max_descendants 是允许的最大descent cgroup 数。
	 */

	/* 层级一下的cg数量 */
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;

	/*
	 * Each non-empty css_set associated with this cgroup contributes
	 * one to nr_populated_csets.  The counter is zero iff this cgroup
	 * doesn't have any tasks.
	 *
	 * All children which have non-zero nr_populated_csets and/or
	 * nr_populated_children of their own contribute one to either
	 * nr_populated_domain_children or nr_populated_threaded_children
	 * depending on their type.  Each counter is zero iff all cgroups
	 * of the type in the subtree proper don't have any tasks.
	  与此 cgroup 关联的每个非空 css_set 都向 nr_populated_csets 贡献一个。
	  如果此 cgroup 没有任何任务，则计数为零。所有具有非零 nr_populated_csets 
	  和/或 nr_populated_children 的子节点
根据其类型向 nr_populated_domain_children 或 nr_populated_threaded_children 
贡献一个。 如果子树中所有类型的 cgroup 都没有任何任务，则每个计数器为零。
	 */
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;

	int nr_threaded_children;	/* # of live threaded child cgroups 实时线程子 cgroups */

	struct kernfs_node *kn;		/* cgroup kernfs entry，cg对应的knode */
	struct cgroup_file procs_file;	/* handle for "cgroup.procs" */
	struct cgroup_file events_file;	/* handle for "cgroup.events" */

	/*
	 * The bitmask of subsystems enabled on the child cgroups.
	 * ->subtree_control is the one configured through
	 * "cgroup.subtree_control" while ->child_ss_mask is the effective
	 * one which may have more subsystems enabled.  Controller knobs
	 * are made available iff it's enabled in ->subtree_control.
	 */
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;

	/* Private pointers for each registered subsystem  每个注册子系统的私有指针*/
	struct cgroup_subsys_state __rcu *subsys[CGROUP_SUBSYS_COUNT];
	
/* root指向了一个cgroupfs_root的结构，就是cgroup所在的层级对应的结构体
2024年06月27日18:23:13
根cg吗 */
	struct cgroup_root *root;

	/*
	 * List of cgrp_cset_links pointing at css_sets with tasks in this
	 * cgroup.  Protected by css_set_lock.
	 指向 css_sets 的 cgrp_cset_links 列表，其中包含此 cgroup 中的任务。
	 2024年07月09日20:32:35
	 是啥？
	 2024年07月10日11:10:18
	 作为表头，连接到有关系的cset，连接件是cgrp cset link。
	 */
	struct list_head cset_links;

	/*
	 * On the default hierarchy, a css_set for a cgroup with some
	 * susbsys disabled will point to css's which are associated with
	 * the closest ancestor which has the subsys enabled.  The
	 * following lists all css_sets which point to this cgroup's css
	 * for the given subsystem.
	 在默认层次结构中，禁用了某些 susbsys 的 cgroup 的 css_set 将指向与启用了 subsys 的最近
	 祖先相关联的 css。
	 下面列出了所有指向给定子系统的 cgroup 的 css 的 css_sets。
	 */
	struct list_head e_csets[CGROUP_SUBSYS_COUNT];

	/*
	 * If !threaded, self.  If threaded, it points to the nearest
	 * domain ancestor.  Inside a threaded subtree, cgroups are exempt
	 * from process granularity and no-internal-task constraint.
	 * Domain level resource consumptions which aren't tied to a
	 * specific task are charged to the dom_cgrp.
	 */
	 /* 如果 !threaded，self。如果线程化，它指向最近的域祖先。 
	 在线程子树中，cgroup 不受进程粒度和无内部任务约束。
	 与特定任务无关的域级资源消耗计入 dom_cgrp。 */
	struct cgroup *dom_cgrp;
	struct cgroup *old_dom_cgrp;		/* used while enabling threaded */

	/* per-cpu recursive resource statistics
	每个 CPU 的递归资源统计。*/
	struct cgroup_rstat_cpu __percpu *rstat_cpu;
	struct list_head rstat_css_list;

	/* cgroup basic resource statistics */
	struct cgroup_base_stat pending_bstat;	/* pending from children */
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;	/* for printing out cputime */

	/*
	 * list of pidlists, up to two for each namespace (one for procs, one
	 * for tasks); created on demand.pidlists 列表，
	 每个命名空间最多两个（一个用于 procs，一个用于tasks），按需创建。
	 */
	struct list_head pidlists;
	struct mutex pidlist_mutex;

	/* used to wait for offlining of csses
	用于等待csses下线 */
	wait_queue_head_t offline_waitq;

	/* used to schedule release agent 用于调度 release agent*/
	struct work_struct release_agent_work;

	/* used to track pressure stalls 用于跟踪pressure stalls */
	struct psi_group psi;

	/* used to store eBPF programs  
	
	用于存放此cg附加的eBPF程序bpf prog*/
	struct cgroup_bpf bpf;

	/* If there is block congestion on this cgroup.用于判断此 cgroup 上是否存在块拥塞。 */
	atomic_t congestion_count;

	/* Used to store internal freezer state用于存储内部freezer状态 */
	struct cgroup_freezer_state freezer;

	/* ids of the ancestors at each level including self
	记录了自己各个层级的祖先，每个级别的祖先的 ID，包括自己。
	2024年07月09日20:51:37
	存储对应层级level的对应祖先的id
		for (tcgrp = cgrp; tcgrp; tcgrp = cgroup_parent(tcgrp)) {
		
		cgrp->ancestor_ids[tcgrp->level] = tcgrp->id;
	 */
	int ancestor_ids[];
};

/*
 * A cgroup_root represents the root of a cgroup hierarchy, and may be
 * associated with a kernfs_root to form an active hierarchy.  This is
 * internal to cgroup core.  Don't access directly from controllers.
 2024年6月24日23:29:35
 cgroup_root 结构代表 cgroup 层次结构的根，并且可以与 kernfs_root 相关联以形成
 活动层次结构。这是 cgroup core内部的，不要直接从控制器访问。
 */
struct cgroup_root {
	struct kernfs_root *kf_root;

	/* The bitmask of subsystems attached to this hierarchy 
	附加到此层次结构的子系统的位掩码。cgroup_init()中 cgrp_dfl_root.subsys_mask 
	在初始化时，已经初始化的子系统在这个mask中。
	2024年07月10日10:45:40
	*/
	unsigned int subsys_mask;

	/* Unique id for this hierarchy. 此层次结构中保持唯一的ID。*/
	int hierarchy_id;

	/* The root cgroup.  Root is destroyed on its release.
	根cgroup */
	struct cgroup cgrp;

	/* for cgrp->ancestor_ids[0] */
	int cgrp_ancestor_id_storage;

	/* Number of cgroups in the hierarchy, used only for /proc/cgroups 
	层次结构中的 cgroup 数量，仅用于 /proc/cgroups*/
	atomic_t nr_cgrps;

	/* A list running through the active hierarchies 遍历活动层次结构的列表 */
	struct list_head root_list;

	/* Hierarchy-specific flags  特定于层次结构的标志*/
	unsigned int flags;

	/* IDs for cgroups in this hierarchy */
	struct idr cgroup_idr;

	/* The path to use for release notifications.用于release notifications的路径。初始化为 ctx->release_agent. */
	char release_agent_path[PATH_MAX];

	/* The name for this hierarchy - may be empty此层次结构的名称，可能为空 */
	char name[MAX_CGROUP_ROOT_NAMELEN];
};

/*
2024年6月30日12:41:15
cgroup各文件节点的定义结构，如 "cgroup.procs"，
主要在 cgroup_init_cftypes 中初始化。
 * struct cftype: handler definitions for cgroup control files
 *
 * When reading/writing to a file:
 *	- the cgroup to use is file->f_path.dentry->d_parent->d_fsdata
 *	- the 'cftype' of the file is file->f_path.dentry->d_fsdata
 */
struct cftype {
	/*
	 * By convention, the name should begin with the name of the
	 * subsystem, followed by a period.  Zero length string indicates
	 * end of cftype array.
	 按照惯例，名称应以子系统的名称开头，后跟一个句点。零长度字符串表示 cftype 数组的结尾
	 */
	char name[MAX_CFTYPE_NAME];
	unsigned long private;

	/*
	 * The maximum length of string, excluding trailing nul, that can
	 * be passed to write.  If < PAGE_SIZE-1, PAGE_SIZE-1 is assumed.
	 可以传递给写入的字符串的最大长度，不包括尾随 nul。 如果 <PAGE_SIZE-1，则假定为 PAGE_SIZE-1。
	 */
	size_t max_write_len;

	/* CFTYPE_* flags 
	cgroup_init()中 ss->dfl_cftypes 中指定的文件节点会或上 __CFTYPE_ONLY_ON_DFL。
	ss->legacy_cftypes 中指定的文件节点会或上 __CFTYPE_NOT_ON_DFL，若二者相同指向，就不会或上任何标志。*/
	unsigned int flags;

	/*
	 * If non-zero, should contain the offset from the start of css to
	 * a struct cgroup_file field.  cgroup will record the handle of
	 * the created file into it.  The recorded handle can be used as
	 * long as the containing css remains accessible.
	 如果非零，则应包含从 css 开始到 struct cgroup_file 字段的偏移量。
	 cgroup 会将创建的文件的句柄记录到其中。只要包含的 css 保持可访问性，就可以使用记录的句柄。
	 */
	unsigned int file_offset;

	/*
	 * Fields used for internal bookkeeping.  Initialized automatically
	 * during registration.
	 */
	struct cgroup_subsys *ss;	/* NULL for cgroup core files 用于内部簿记的字段。 注册时自动初始化。 */
	struct list_head node;		/* anchored at ss->cfts */
	/* cgroup_init_cftypes: 若文件节点实现了.seq_start 回调就指向全局
	cgroup_kf_ops，否则指向全局 cgroup_kf_single_ops。 */
	struct kernfs_ops *kf_ops;

	int (*open)(struct kernfs_open_file *of);
	void (*release)(struct kernfs_open_file *of);

	/*
	 * read_u64() is a shortcut for the common case of returning a
	 * single integer. Use it in place of read()
	 */
	u64 (*read_u64)(struct cgroup_subsys_state *css, struct cftype *cft);
	/*
	 * read_s64() is a signed version of read_u64()
	 */
	s64 (*read_s64)(struct cgroup_subsys_state *css, struct cftype *cft);

	/* generic seq_file read interface */
	int (*seq_show)(struct seq_file *sf, void *v);

	/* optional ops, implement all or none */
	void *(*seq_start)(struct seq_file *sf, loff_t *ppos);
	void *(*seq_next)(struct seq_file *sf, void *v, loff_t *ppos);
	void (*seq_stop)(struct seq_file *sf, void *v);

	/*
	 * write_u64() is a shortcut for the common case of accepting
	 * a single integer (as parsed by simple_strtoull) from
	 * userspace. Use in place of write(); return 0 or error.
	 */
	int (*write_u64)(struct cgroup_subsys_state *css, struct cftype *cft,
			 u64 val);
	/*
	 * write_s64() is a signed version of write_u64()
	 */
	int (*write_s64)(struct cgroup_subsys_state *css, struct cftype *cft,
			 s64 val);

	/*
	 * write() is the generic write callback which maps directly to
	 * kernfs write operation and overrides all other operations.
	 * Maximum write size is determined by ->max_write_len.  Use
	 * of_css/cft() to access the associated css and cft.
	 */
	ssize_t (*write)(struct kernfs_open_file *of,
			 char *buf, size_t nbytes, loff_t off);

	__poll_t (*poll)(struct kernfs_open_file *of,
			 struct poll_table_struct *pt);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lock_class_key	lockdep_key;
#endif
};

/*
 * Control Group subsystem type.
 * See Documentation/admin-guide/cgroup-v1/cgroups.rst for details
 memory_cgrp_subsys实现了memcg操作集
 2024年06月21日14:12:48
 2024年07月09日19:58:16
 
 */
struct cgroup_subsys {
	struct cgroup_subsys_state *(*css_alloc)(struct cgroup_subsys_state *parent_css);
	int (*css_online)(struct cgroup_subsys_state *css);
	void (*css_offline)(struct cgroup_subsys_state *css);
	/* 对应的css被释放后，调用此 */
	void (*css_released)(struct cgroup_subsys_state *css);
	void (*css_free)(struct cgroup_subsys_state *css);
	void (*css_reset)(struct cgroup_subsys_state *css);
	void (*css_rstat_flush)(struct cgroup_subsys_state *css, int cpu);
	int (*css_extra_stat_show)(struct seq_file *seq,
				   struct cgroup_subsys_state *css);

	int (*can_attach)(struct cgroup_taskset *tset);
	void (*cancel_attach)(struct cgroup_taskset *tset);
	void (*attach)(struct cgroup_taskset *tset);
	void (*post_attach)(void);
	int (*can_fork)(struct task_struct *task);
	void (*cancel_fork)(struct task_struct *task);
	void (*fork)(struct task_struct *task);
	/* 子系统处理进程退出时候的回调 */
	void (*exit)(struct task_struct *task);
	void (*release)(struct task_struct *task);
	void (*bind)(struct cgroup_subsys_state *root_css);

	bool early_init:1;

	/*
	 * If %true, the controller, on the default hierarchy, doesn't show
	 * up in "cgroup.controllers" or "cgroup.subtree_control", is
	 * implicitly enabled on all cgroups on the default hierarchy, and
	 * bypasses the "no internal process" constraint.  This is for
	 * utility type controllers which is transparent to userland.
	 *
	 * An implicit controller can be stolen from the default hierarchy
	 * anytime and thus must be okay with offline csses from previous
	 * hierarchies coexisting with csses for the current one.
	 */
	bool implicit_on_dfl:1;

	/*
	 * If %true, the controller, supports threaded mode on the default
	 * hierarchy.  In a threaded subtree, both process granularity and
	 * no-internal-process constraint are ignored and a threaded
	 * controllers should be able to handle that.
	 *
	 * Note that as an implicit controller is automatically enabled on
	 * all cgroups on the default hierarchy, it should also be
	 * threaded.  implicit && !threaded is not supported.
	 */
	bool threaded:1;

	/*
	 * If %false, this subsystem is properly hierarchical -
	 * configuration, resource accounting and restriction on a parent
	 * cgroup cover those of its children.  If %true, hierarchy support
	 * is broken in some ways - some subsystems ignore hierarchy
	 * completely while others are only implemented half-way.
	 *
	 * It's now disallowed to create nested cgroups if the subsystem is
	 * broken and cgroup core will emit a warning message on such
	 * cases.  Eventually, all subsystems will be made properly
	 * hierarchical and this will go away.
	 */
	bool broken_hierarchy:1;
	bool warned_broken_hierarchy:1;

	/* the following two fields are initialized automtically during boot
	子系统的id */
	int id;
	/* 子系统的名字 */
	const char *name;

	/* optional, initialized automatically during boot if not set */
	const char *legacy_name;

	/* link to parent, protected by cgroup_lock()
	
	 */
	struct cgroup_root *root;

	/* idr for css->id
	idr查找 */
	struct idr css_idr;

	/*
	 * List of cftypes.  Each entry is the first entry of an array
	 * terminated by zero length name.
	 */
	struct list_head cfts;

	/*
	 * Base cftypes which are automatically registered.  The two can
	 * point to the same array.
	 */
	struct cftype *dfl_cftypes;	/* for the default hierarchy */
	struct cftype *legacy_cftypes;	/* for the legacy hierarchies */

	/*
	 * A subsystem may depend on other subsystems.  When such subsystem
	 * is enabled on a cgroup, the depended-upon subsystems are enabled
	 * together if available.  Subsystems enabled due to dependency are
	 * not visible to userland until explicitly enabled.  The following
	 * specifies the mask of subsystems that this one depends on.
	 */
	unsigned int depends_on;
};

extern struct percpu_rw_semaphore cgroup_threadgroup_rwsem;

/**
 * cgroup_threadgroup_change_begin - threadgroup exclusion for cgroups
 * @tsk: target task
 *
 * Allows cgroup operations to synchronize against threadgroup changes
 * using a percpu_rw_semaphore.
 */
static inline void cgroup_threadgroup_change_begin(struct task_struct *tsk)
{
	percpu_down_read(&cgroup_threadgroup_rwsem);
}

/**
 * cgroup_threadgroup_change_end - threadgroup exclusion for cgroups
 * @tsk: target task
 *
 * Counterpart of cgroup_threadcgroup_change_begin().
 */
static inline void cgroup_threadgroup_change_end(struct task_struct *tsk)
{
	percpu_up_read(&cgroup_threadgroup_rwsem);
}

#else	/* CONFIG_CGROUPS */

#define CGROUP_SUBSYS_COUNT 0

static inline void cgroup_threadgroup_change_begin(struct task_struct *tsk)
{
	might_sleep();
}

static inline void cgroup_threadgroup_change_end(struct task_struct *tsk) {}

#endif	/* CONFIG_CGROUPS */

#ifdef CONFIG_SOCK_CGROUP_DATA

/*

2024年06月24日18:34:30
sock的cgrp
 * sock_cgroup_data is embedded at sock->sk_cgrp_data and contains
 * per-socket cgroup information except for memcg association.
 *
 * On legacy hierarchies, net_prio and net_cls controllers directly set
 * attributes on each sock which can then be tested by the network layer.
 * On the default hierarchy, each sock is associated with the cgroup it was
 * created in and the networking layer can match the cgroup directly.
 *
 * To avoid carrying all three cgroup related fields separately in sock,
 * sock_cgroup_data overloads (prioidx, classid) and the cgroup pointer.
 * On boot, sock_cgroup_data records the cgroup that the sock was created
 * in so that cgroup2 matches can be made; however, once either net_prio or
 * net_cls starts being used, the area is overriden to carry prioidx and/or
 * classid.  The two modes are distinguished by whether the lowest bit is
 * set.  Clear bit indicates cgroup pointer while set bit prioidx and
 * classid.
 *
 * While userland may start using net_prio or net_cls at any time, once
 * either is used, cgroup2 matching no longer works.  There is no reason to
 * mix the two and this is in line with how legacy and v2 compatibility is
 * handled.  On mode switch, cgroup references which are already being
 * pointed to by socks may be leaked.  While this can be remedied by adding
 * synchronization around sock_cgroup_data, given that the number of leaked
 * cgroups is bound and highly unlikely to be high, this seems to be the
 * better trade-off.
 */
struct 
sock_cgroup_data {
	union {
#ifdef __LITTLE_ENDIAN
		struct {
			u8	is_data;
			u8	padding;
			u16	prioidx;
			u32	classid;
		} __packed;
#else
		struct {
			u32	classid;
			u16	prioidx;
			u8	padding;
			u8	is_data;
		} __packed;
#endif
		u64		val;
	};
};

/*
 * There's a theoretical window where the following accessors race with
 * updaters and return part of the previous pointer as the prioidx or
 * classid.  Such races are short-lived and the result isn't critical.
 */
static inline u16 sock_cgroup_prioidx(const struct sock_cgroup_data *skcd)
{
	/* fallback to 1 which is always the ID of the root cgroup */
	return (skcd->is_data & 1) ? skcd->prioidx : 1;
}

static inline u32 sock_cgroup_classid(const struct sock_cgroup_data *skcd)
{
	/* fallback to 0 which is the unconfigured default classid */
	return (skcd->is_data & 1) ? skcd->classid : 0;
}

/*
 * If invoked concurrently, the updaters may clobber each other.  The
 * caller is responsible for synchronization.
 */
static inline void sock_cgroup_set_prioidx(struct sock_cgroup_data *skcd,
					   u16 prioidx)
{
	struct sock_cgroup_data skcd_buf = {{ .val = READ_ONCE(skcd->val) }};

	if (sock_cgroup_prioidx(&skcd_buf) == prioidx)
		return;

	if (!(skcd_buf.is_data & 1)) {
		skcd_buf.val = 0;
		skcd_buf.is_data = 1;
	}

	skcd_buf.prioidx = prioidx;
	WRITE_ONCE(skcd->val, skcd_buf.val);	/* see sock_cgroup_ptr() */
}

static inline void sock_cgroup_set_classid(struct sock_cgroup_data *skcd,
					   u32 classid)
{
	struct sock_cgroup_data skcd_buf = {{ .val = READ_ONCE(skcd->val) }};

	if (sock_cgroup_classid(&skcd_buf) == classid)
		return;

	if (!(skcd_buf.is_data & 1)) {
		skcd_buf.val = 0;
		skcd_buf.is_data = 1;
	}

	skcd_buf.classid = classid;
	WRITE_ONCE(skcd->val, skcd_buf.val);	/* see sock_cgroup_ptr() */
}

#else	/* CONFIG_SOCK_CGROUP_DATA */

struct sock_cgroup_data {
};

#endif	/* CONFIG_SOCK_CGROUP_DATA */

#endif	/* _LINUX_CGROUP_DEFS_H */
