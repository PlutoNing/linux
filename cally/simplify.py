import re


def extract_words(large_string):
    tmp_set = set(re.findall(r"[a-zA-Z_0-9]\w*", large_string))
    res_set = {item for item in tmp_set if not re.match(r"^\d+$", item)}
    return res_set


def filter_dot_file(dot_file_path, words):
    with open(dot_file_path, "r") as file:
        lines = file.readlines()

    with open(dot_file_path, "w") as file:
        for line in lines:
            if not any(word in line for word in words):
                file.write(line)


if __name__ == "__main__":
    dot_file_path = "/mnt/n7000/paulning/study/linux/mm/page-writeback.dot"
    trivial_func = """
    __bpf_trace_mm_filemap_op_page_cache
folio_wait_bit_killable
debug_lockdep_rcu_enabled
__count_memcg_events
__probestub_file_check_and_advance_wb_err
__tsan_volatile_write8
__tsan_volatile_write4
__tsan_write2
__folio_put
__tsan_init
__SCT__tp_func_filemap_set_wb_err
file_remove_privs
__tsan_atomic_signal_fence
perf_trace_filemap_set_wb_err
dump_stack
mem_cgroup_from_task
set_pte_range
bpf_trace_run1
__tsan_read1
perf_trace_buf_alloc
__bpf_trace_filemap_set_wb_err
trace_event_buffer_reserve
lockdep_rcu_suspicious
xas_find
folio_flags
filemap_invalidate_unlock_two
trace_raw_output_mm_filemap_op_page_cache
folio_wait_private_2_killable
psi_memstall_leave
rcu_read_lock_any_held
_printk
folio_end_private_2
folio_put
rcu_is_watching
__SCT__tp_func_file_check_and_advance_wb_err
__sanitizer_cov_trace_const_cmp8
xas_split_alloc
__kcsan_check_access
file_path
__tsan_read4
__traceiter_mm_filemap_delete_from_page_cache
_raw_spin_unlock_irqrestore
__tsan_write8
preempt_count_sub
folio_wait_private_2
__probestub_mm_filemap_delete_from_page_cache
__might_sleep
generic_file_mmap
__xas_next
__traceiter_mm_filemap_add_to_page_cache
trace_hardirqs_on
page_cache_prev_miss
wake_up_state
__fdget
_copy_to_user
trace_event_raw_event_mm_filemap_op_page_cache
find_get_entries
__mod_lruvec_page_state
__SCT__might_resched
__tsan_write1
fput
rcu_read_lock_held
__folio_lock_or_retry
__rcu_read_lock
xas_nomem
__ubsan_handle_load_invalid_value
down_write_nested
trace_raw_output_filemap_set_wb_err
lock_release
folio_test_uptodate
folio_wake_bit
xa_get_order
trace_raw_output_prep
__tsan_func_exit
__SCT__tp_func_mm_filemap_delete_from_page_cache
rcuwait_wake_up
touch_atime
lock_is_held_type
__tsan_read8
_raw_spin_lock_irqsave
perf_trace_file_check_and_advance_wb_err
__trace_trigger_soft_disabled
errseq_check_and_advance
xas_init_marks
up_write
io_schedule
trace_event_raw_event_file_check_and_advance_wb_err
_raw_spin_lock
__folio_alloc
folio_unlock
bpf_trace_run2
trace_event_printf
__folio_lock
lock_acquire
iov_iter_revert
__ubsan_handle_shift_out_of_bounds
xas_load
swp_offset_pfn
_compound_head
__bpf_trace_file_check_and_advance_wb_err
kcsan_atomic_next
_raw_spin_lock_irq
__traceiter_file_check_and_advance_wb_err
__filemap_set_wb_err
perf_trace_run_bpf_submit
folio_alloc
folio_wait_bit
__tsan_write_range
__tsan_read2
down_read
_raw_spin_unlock
rcu_read_unlock
folio_add_wait_queue
wake_page_function
__mmap_lock_do_trace_released
filemap_invalidate_lock_two
__folio_lock_killable
errseq_check
__SCT__tp_func_wbc_writepage
mod_timer
__ubsan_handle_divrem_overflow
__percpu_counter_sum
wb_get_create_current.constprop.0
__sanitizer_cov_trace_cmp4
page_cache_next_miss
css_put
css_tryget
unlock_page
folio_mapping
__mod_node_page_state
__SCT__tp_func_writeback_dirty_folio
kcsan_set_access_mask
percpu_counter_add_batch
kcsan_set_access_mask
__this_cpu_preempt_check
__mod_zone_page_state
__inode_attach_wb
folio_memcg_unlock
folio_memcg_lock
timer_delete
"tag_pages_for_writeback" -> "xas_set_mark";

__SCT__tp_func_folio_wait_writeback
inode_to_bdi
__page_ref_mod
__SCT__cond_resched
__sanitizer_cov_trace_const_cmp1
trace_hardirqs_off
xas_store
trace_handle_return
__list_del_entry_valid_or_report
__sanitizer_cov_trace_pc
__sanitizer_cov_trace_cmp8
__traceiter_filemap_set_wb_err
__probestub_mm_filemap_add_to_page_cache
pmd_install
__tsan_volatile_read4
__page_ref_mod_unless
preempt_count_add
_raw_spin_unlock_irq
trace_event_buffer_commit
__SCT__tp_func_mm_filemap_add_to_page_cache
__tsan_volatile_read8
xas_split
up_read
down_write
folio_wait_bit_common
errseq_set
__might_resched
perf_trace_mm_filemap_op_page_cache
__sanitizer_cov_trace_const_cmp2
xas_reload
__percpu_down_read
psi_memstall_enter
_copy_from_user
__sanitizer_cov_trace_const_cmp4
filemap_get_folios
xas_pause
do_set_pmd
xas_find_conflict
__tsan_write4
warn_bogus_irq_restore
__pte_offset_map_lock
__tsan_func_entry
down_read_trylock
__rcu_read_unlock
__xas_prev
__probestub_filemap_set_wb_err
trace_raw_output_file_check_and_advance_wb_err
___ratelimit
__list_add_valid_or_report
xas_find_marked
__ubsan_handle_out_of_bounds
generic_file_readonly_mmap
xa_load
finish_wait
__page_ref_mod_and_test
__stack_chk_fail
trace_event_raw_event_filemap_set_wb_err
xas_next_entry
dump_page
file_update_time
    """

    large_string = (
        trivial_func
        + """     48 rcu_is_watching
     48 __sanitizer_cov_trace_cmp8
     50 debug_lockdep_rcu_enabled
     50 lockdep_rcu_suspicious
     50 __ubsan_handle_load_invalid_value
     54 dump_page
     56 folio_flags
     58 __ubsan_handle_out_of_bounds
     62 __tsan_read1
     62 __tsan_volatile_read4
     66 __tsan_atomic_signal_fence
     70 __tsan_write1
     72 __tsan_write4
     82 __stack_chk_fail
     92 __tsan_write8
    112 __tsan_read4
    114 __sanitizer_cov_trace_const_cmp8
    128 __kcsan_check_access
    132 __tsan_volatile_read8
    140 __sanitizer_cov_trace_const_cmp4
    150 __sanitizer_cov_trace_const_cmp1
    162 __tsan_read8
    248 __sanitizer_cov_trace_pc
    248 __tsan_func_entry
    248 __tsan_func_exit"""
    )

    words = extract_words(large_string)

    filter_dot_file(dot_file_path, words)
