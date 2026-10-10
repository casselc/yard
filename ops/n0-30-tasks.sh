#!/bin/sh
# n0-30-tasks.sh -- N0: per-task uid range, login class, rctl user: scheme, minimal devfs ruleset,
#                   service accounts, module preloads.
# PURPOSE   Phase 0 (spike 22) showed RCTL limits are per-jail and NOT hierarchical: a parent jail rule
#           does not cap its children. So a task's aggregate cap comes from running every process of the
#           task under ONE task uid and putting `user:<uid>:...` rules on it (they aggregate across jails);
#           per-call memory caps go on each child jail (`jail:<name>:vmemoryuse:deny=...`). This step
#           installs the fixed parts of that scheme; yard-spawn adds/removes the per-task and per-call
#           rules at runtime with rctl_add_rule(2)/rctl_remove_rule(2).
#             task uids     2000000-2099999 (100k; never in /etc/passwd; pw(8) allocates below 32000)
#             task group    _yardtask, gid 2000000 (every task uid's primary gid)
#             login class   yard_task in /etc/login.conf: the exec shim applies its rlimits/priority/umask
#                           with setusercontext() BEFORE jail_attach (inside the jail the jail's own
#                           login.conf would be read)
#             per-task rctl (yard-spawn, at task start; removed at task end):
#                           user:<uid>:maxproc:deny=512  user:<uid>:openfiles:deny=16384
#                           user:<uid>:vmemoryuse:deny=8g user:<uid>:pcpu:deny=200 (2 of 4 cores)
#                           Values live in /usr/local/etc/yard/tasks.conf so they can change without a rebuild.
#             devfs         ruleset 10 "yard_min": hide all, unhide null zero random urandom crypto fd stdio
#             accounts      _sign (uid 830) for the signer, _yard (uid 831) for yard-ctl; nologin, no home
#             preloads      if_epair_load=YES in loader.conf; rctl_enable=YES (kern.racct.enable=1 is already set)
# PREDICT   `pw groupshow _yardtask` -> gid 2000000; cap_mkdb succeeds; `devfs rule -s 10 show` lists 11 rules;
#           `id _sign` uid 830, `id _yard` uid 831; `sysrc rctl_enable` YES. Under 5 s.
# CHANGES   /etc/login.conf (+cap_mkdb), /etc/devfs.rules, /etc/group, /etc/master.passwd (2 accounts),
#           /usr/local/etc/yard/tasks.conf, rc.conf rctl_enable, loader.conf if_epair_load; loads if_epair.
#           Originals of edited files kept in ops/state/orig/.
# UNDO      sudo sh n0-30-tasks-undo.sh
# RUNTIME   seconds.
. "$(dirname "$0")/lib.sh"
step_wrap n0-30-tasks "$0" "$@"
TASK_UID_MIN=2000000; TASK_UID_MAX=2099999; TASK_GID=2000000

# --- group and service accounts
if pw groupshow _yardtask >/dev/null 2>&1; then say "group _yardtask exists: $(pw groupshow _yardtask)"
else
	pw groupshow -g $TASK_GID >/dev/null 2>&1 && die "gid $TASK_GID already used by $(pw groupshow -g $TASK_GID)"
	pw groupadd _yardtask -g $TASK_GID; echo group:_yardtask >>"$STATE/accounts-created"; say "created group _yardtask gid $TASK_GID"
fi
acct() { # acct NAME UID GECOS
	if pw usershow "$1" >/dev/null 2>&1; then say "user $1 exists: $(id "$1")"; return; fi
	pw usershow -u "$2" >/dev/null 2>&1 && die "uid $2 already used by $(pw usershow -u "$2")"
	pw groupshow -g "$2" >/dev/null 2>&1 && die "gid $2 already used"
	pw groupadd "$1" -g "$2"
	pw useradd "$1" -u "$2" -g "$1" -c "$3" -d /nonexistent -s /usr/sbin/nologin -h -
	echo "user:$1" >>"$STATE/accounts-created"; say "created $(id "$1")"
}
acct _sign 830 "yard STS signer"
acct _yard 831 "yard control plane"

# --- login class
if grep -q '^yard_task:' /etc/login.conf; then say "login class yard_task present"
else
	backup_once /etc/login.conf
	cat >>/etc/login.conf <<'LCEOF'

# yard per-task class (ops/n0-30-tasks.sh). Applied by yard-exec-shim via setusercontext() before
# jail_attach. Aggregate caps across all of a task's processes are rctl user: rules, not these.
yard_task:\
	:maxproc=512:\
	:openfiles=4096:\
	:coredumpsize=0:\
	:stacksize=64M:\
	:priority=5:\
	:umask=022:\
	:tc=default:
LCEOF
	say "appended class yard_task to /etc/login.conf"
fi
cap_mkdb /etc/login.conf
say "login.conf.db rebuilt"

# --- tasks.conf (read by yard-spawn)
mkdir -p $ETC
cat >$STATE/tasks.conf <<TCEOF
# yard per-task identity and limits (ops/n0-30-tasks.sh). Read by yard-spawn.
task_uid_min=$TASK_UID_MIN
task_uid_max=$TASK_UID_MAX
task_gid=$TASK_GID
task_login_class=yard_task
# rctl rules yard-spawn adds as user:<uid>:<rule> at task start and removes at task end
task_rctl=maxproc:deny=512 openfiles:deny=16384 vmemoryuse:deny=8g pcpu:deny=200
# devfs ruleset for per-call child jails
devfs_ruleset=10
TCEOF
if [ -f $ETC/tasks.conf ] && cmp -s $STATE/tasks.conf $ETC/tasks.conf; then say "$ETC/tasks.conf up to date"
else [ -f $ETC/tasks.conf ] || echo "$ETC/tasks.conf" >>"$STATE/files-created"; install -m 0644 $STATE/tasks.conf $ETC/tasks.conf; say "installed $ETC/tasks.conf"; fi

# --- devfs ruleset 10
if grep -q '^\[yard_min=10\]' /etc/devfs.rules 2>/dev/null; then say "devfs ruleset yard_min=10 present"
else
	backup_once /etc/devfs.rules
	cat >>/etc/devfs.rules <<'DREOF'

# yard minimal devfs for per-call child jails (ops/n0-30-tasks.sh)
[yard_min=10]
add hide
add path null unhide
add path zero unhide
add path random unhide
add path urandom unhide
add path crypto unhide
add path fd unhide
add path 'fd/*' unhide
add path stdin unhide
add path stdout unhide
add path stderr unhide
DREOF
	say "added ruleset yard_min=10 to /etc/devfs.rules"
fi
service devfs restart
devfs rule -s 10 show | sed 's/^/    /'

# --- rctl and module preloads
rc_set rctl_enable YES
rc_set if_epair_load YES /boot/loader.conf
kldstat -q -n if_epair || kldstat -q -m if_epair || { kldload if_epair && echo if_epair >>"$STATE/kld-loaded"; say "loaded if_epair"; }
say "kern.racct.enable=$(sysctl -n kern.racct.enable) (must be 1; it is a boot-time tunable)"
say "OK"
