/* Trace only the mount command and its children. No file contents or keys. */
#pragma D option quiet
#pragma D option aggsize=4m

fbt::zil_replay:entry,
fbt::zil_replay_log_record:entry,
fbt::zil_destroy:entry,
fbt::zfs_unlinked_drain:entry,
fbt::zfs_rmnode:entry,
fbt::dsl_dataset_dirty:entry
/pid == $target || progenyof($target)/
{
	@calls[probefunc] = count();
	@callstacks[probefunc, stack(12)] = count();
}

fbt::zil_destroy:entry
/pid == $target || progenyof($target)/
{
	self->destroy = 1;
}

fbt::zil_destroy:return
/self->destroy/
{
	/* FreeBSD x86 fbt_isa.c passes (return-offset, tf_rax): arg1 is
	 * the return value. The inspected OpenZFS function returns boolean_t. */
	@destroy_results[arg1] = count();
	self->destroy = 0;
}

fbt::dnode_setdirty:entry
/pid == $target || progenyof($target)/
{
	this->dn = (struct dnode *)arg0;
	@dirty_objects[this->dn->dn_object, this->dn->dn_type] = count();
	@object_stacks[this->dn->dn_object, this->dn->dn_type, stack(12)] = count();
}

fbt::dmu_buf_will_dirty:entry
/pid == $target || progenyof($target)/
{
	this->db = (dmu_buf_t *)arg0;
	@dirty_buffers[this->db->db_object, this->db->db_offset, this->db->db_size] = count();
}

ERROR
{
	printf("TRACE ERROR: attribution is incomplete\n");
	/* Let the bounded -c command finish; the wrapper rejects this trace.
	 * Exiting here could leave that child mounting while cleanup runs. */
	@trace_errors = count();
}

END
{
	printf("\nMount-thread call counts:\n");
	printa("%-32s %@d\n", @calls);
	printf("\nZIL destroy returns (informational; inspected 2.4.4 true path commits a dirty-dataset transaction):\n");
	printa("result=%d count=%@d\n", @destroy_results);
	printf("\nDirtied objects (object number, DMU type):\n");
	printa("object=%d type=%d count=%@d\n", @dirty_objects);
	printf("\nDirtied buffers (object number, offset, size):\n");
	printa("object=%d offset=%d size=%d count=%@d\n", @dirty_buffers);
	printf("\nCall stacks:\n");
	printa(@callstacks);
	printf("\nObject dirty stacks:\n");
	printa(@object_stacks);
	printf("\nScope: mount command and descendants; background TXG workers are not attributed.\n");
}
