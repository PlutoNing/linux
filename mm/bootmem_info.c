// SPDX-License-Identifier: GPL-2.0
/*
 * Bootmem core functions.
 *
 * Copyright (c) 2020, Bytedance.
 *
 *     Author: Muchun Song <songmuchun@bytedance.com>
 *
 */
#include <linux/mm.h>
#include <linux/compiler.h>
#include <linux/memblock.h>
#include <linux/bootmem_info.h>
#include <linux/memory_hotplug.h>
#include <linux/kmemleak.h>

/*
参数info是nid, page是此node的pgdat结构体所在的数据页, 一般有好几个
*/
void get_page_bootmem(unsigned long info, struct page *page, unsigned long type)
{
	page->index = type;
	SetPagePrivate(page);
	set_page_private(page, info);
	page_ref_inc(page);
}

void put_page_bootmem(struct page *page)
{
	unsigned long type = page->index;

	BUG_ON(type < MEMORY_HOTPLUG_MIN_BOOTMEM_TYPE ||
	       type > MEMORY_HOTPLUG_MAX_BOOTMEM_TYPE);

	if (page_ref_dec_return(page) == 1) {
		page->index = 0;
		ClearPagePrivate(page);
		set_page_private(page, 0);
		INIT_LIST_HEAD(&page->lru);
		kmemleak_free_part(page_to_virt(page), PAGE_SIZE);
		free_reserved_page(page);
	}
}

#ifndef CONFIG_SPARSEMEM_VMEMMAP
static void __init register_page_bootmem_info_section(unsigned long start_pfn)
{
	unsigned long mapsize, section_nr, i;
	struct mem_section *ms;
	struct page *page, *memmap;
	struct mem_section_usage *usage;

	section_nr = pfn_to_section_nr(start_pfn);
	ms = __nr_to_section(section_nr);

	/* Get section's memmap address */
	memmap = sparse_decode_mem_map(ms->section_mem_map, section_nr);

	/*
	 * Get page for the memmap's phys address
	 * XXX: need more consideration for sparse_vmemmap...
	 */
	page = virt_to_page(memmap);
	mapsize = sizeof(struct page) * PAGES_PER_SECTION;
	mapsize = PAGE_ALIGN(mapsize) >> PAGE_SHIFT;

	/* remember memmap's page */
	for (i = 0; i < mapsize; i++, page++)
		get_page_bootmem(section_nr, page, SECTION_INFO);

	usage = ms->usage;
	page = virt_to_page(usage);

	mapsize = PAGE_ALIGN(mem_section_usage_size()) >> PAGE_SHIFT;

	for (i = 0; i < mapsize; i++, page++)
		get_page_bootmem(section_nr, page, MIX_SECTION_INFO);

}
#else /* CONFIG_SPARSEMEM_VMEMMAP */
/*
在把bootmem放入buudy之后调用
处理每一个node, 这里好像就是把各种page设置了一下type?
start_pfn是node的每一个memsection的起始pfn
*/
static void __init register_page_bootmem_info_section(unsigned long start_pfn)
{
	unsigned long mapsize, section_nr, i;
	struct mem_section *ms;
	struct page *page, *memmap;
	struct mem_section_usage *usage;
	/* 找到pfn对应的memsection */
	section_nr = pfn_to_section_nr(start_pfn);
	ms = __nr_to_section(section_nr);

	memmap = sparse_decode_mem_map(ms->section_mem_map, section_nr);
	// 处理此ms的每一个page的顶层pmd.pud,p4d,pgd页表页面的ref和type什么的 , 完成之后可以-exec  p (*(struct page*)0xffffea0008dbffc0)查看index, ref什么的
	register_page_bootmem_memmap(section_nr, memmap, PAGES_PER_SECTION);
	/* 这里同样方式处理ms->usage所使用的page结构体的type和ref */
	usage = ms->usage;
	page = virt_to_page(usage);

	mapsize = PAGE_ALIGN(mem_section_usage_size()) >> PAGE_SHIFT;

	for (i = 0; i < mapsize; i++, page++)
		get_page_bootmem(section_nr, page, MIX_SECTION_INFO);
}
#endif /* !CONFIG_SPARSEMEM_VMEMMAP */

// bootmem过程中把memblock页面放入buudy之后调用, 处理页表页面, memsection map页面page结构体的ref
void __init register_page_bootmem_info_node(struct pglist_data *pgdat)
{
	unsigned long i, pfn, end_pfn, nr_pages;
	int node = pgdat->node_id;
	struct page *page;

	// 存放这个node结构体需要几个页面? 有情况是6个
	nr_pages = PAGE_ALIGN(sizeof(struct pglist_data)) >> PAGE_SHIFT;
	page = virt_to_page(pgdat);

	for (i = 0; i < nr_pages; i++, page++) //遍历处理node结构体所在的nr_page个页面
		get_page_bootmem(node, page, NODE_INFO); /* 设置page type, 设置priv, 处理ref */

	pfn = pgdat->node_start_pfn;
	end_pfn = pgdat_end_pfn(pgdat);

	/* register section info */
	for (; pfn < end_pfn; pfn += PAGES_PER_SECTION) {/* 遍历node的每一个ms的起始页面 */
		/*
		 * Some platforms can assign the same pfn to multiple nodes - on
		 * node0 as well as nodeN.  To avoid registering a pfn against
		 * multiple nodes we check that this pfn does not already
		 * reside in some other nodes.
		 */
		if (pfn_valid(pfn) && (early_pfn_to_nid(pfn) == node))
			register_page_bootmem_info_section(pfn); // 处理这个memsection
		// 好像里面会处理页表的page, usemap的page之类page的ref,index, 整体来说是一个get的逻辑
	}
}
