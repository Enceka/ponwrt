from pathlib import Path
import difflib
import hashlib
import json
import subprocess

root = Path(__file__).resolve().parent
source = root/'candidate/net/bridge/br_fdb.c'
original = source.read_text()
modified = source.read_text()

def function(text, signature):
    begin = text.index(signature)
    braces = 0
    start = text.index('{', begin)
    for index in range(start, len(text)):
        braces += (text[index] == '{') - (text[index] == '}')
        if not braces:
            return text[begin:index+1]
    raise AssertionError(signature)

prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef uint16_t u16;
struct net_device { const char *name; };
struct net_bridge_port { struct net_device *dev; };
struct net_bridge { struct net_device *dev; int fdb_hash_tbl,hash_lock,fdb_n_learned; };
struct net_bridge_fdb_entry { struct net_bridge_port *dst; unsigned long flags,updated; };
enum { BR_FDB_LOCAL,BR_FDB_STICKY,BR_FDB_ADDED_BY_EXT_LEARN,BR_FDB_LOCKED,
       BR_FDB_ADDED_BY_USER,BR_FDB_DYNAMIC_LEARNED,BR_FDB_NOTIFY_INACTIVE };
enum { RTM_NEWNEIGH,RTM_DELNEIGH };
static unsigned long jiffies=100;
static int pre_error,begins,ends,deletes,notifies,traces;
static struct net_bridge_fdb_entry entry;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define likely(x) (x)
#define unlikely(x) (x)
#define br_warn(...) ((void)0)
#define spin_lock(x) ((void)(x))
#define spin_unlock(x) ((void)(x))
#define trace_br_fdb_update(...) (++traces)
static int test_bit(int bit,const unsigned long *flags) { return !!(*flags & (1ul<<bit)); }
static void clear_bit(int bit,unsigned long *flags) { *flags &= ~(1ul<<bit); }
static void set_bit(int bit,unsigned long *flags) { *flags |= 1ul<<bit; }
static int test_and_clear_bit(int bit,unsigned long *flags) { int set=test_bit(bit,flags);clear_bit(bit,flags);return set; }
static int hold_time(struct net_bridge *br) { (void)br;return 1; }
static int net_ratelimit(void) { return 0; }
static void atomic_dec(int *value) { --*value; }
static struct net_bridge_fdb_entry *fdb_find_rcu(int *table,const unsigned char *addr,u16 vid) { (void)table;(void)addr;(void)vid;return &entry; }
static struct net_bridge_fdb_entry *fdb_create(struct net_bridge *br,struct net_bridge_port *port,const unsigned char *addr,u16 vid,unsigned long flags) { (void)br;(void)port;(void)addr;(void)vid;(void)flags;return 0; }
static int br_flow_offload_begin(struct net_device *dev) { (void)dev;++begins;return pre_error; }
static void br_flow_offload_end(struct net_device *dev) { (void)dev;++ends; }
static void br_switchdev_fdb_notify(struct net_bridge *br,struct net_bridge_fdb_entry *fdb,int event) { (void)br;(void)fdb;assert(event==RTM_DELNEIGH && begins==1 && ends==0 && !pre_error);++deletes; }
static void fdb_notify(struct net_bridge *br,struct net_bridge_fdb_entry *fdb,int event,bool notify) { (void)br;(void)fdb;(void)notify;assert(event==RTM_NEWNEIGH);++notifies; }
'''
suffix = r'''
static void reset(struct net_bridge_port *old) {
    entry=(struct net_bridge_fdb_entry){.dst=old,.updated=1,
      .flags=(1ul<<BR_FDB_ADDED_BY_EXT_LEARN)|(1ul<<BR_FDB_LOCKED)|(1ul<<BR_FDB_NOTIFY_INACTIVE)};
    begins=ends=deletes=notifies=traces=0;
}
int main(void) {
    struct net_device dev={.name="test"};
    struct net_bridge br={.dev=&dev};
    struct net_bridge_port old={.dev=&dev},new={.dev=&dev};
    const unsigned char addr[6]={0};
    for(int error=1;error<=3;error++) {
        reset(&old);pre_error=-error;
        struct net_bridge_fdb_entry saved=entry;
        br_fdb_update(&br,&new,addr,0,0);
        assert(!memcmp(&saved,&entry,sizeof(entry)));
        assert(begins==1 && ends==1 && !deletes && !notifies && !traces);
    }
    reset(&old);pre_error=0;
    br_fdb_update(&br,&new,addr,0,0);
    assert(entry.dst==&new && entry.updated==jiffies && !entry.flags);
    assert(begins==1 && ends==1 && deletes==1 && notifies==1 && traces==1);
    reset(&old);pre_error=-5;
    br_fdb_update(&br,&old,addr,0,0);
    assert(entry.dst==&old && entry.updated==jiffies && !begins && !ends && !deletes);
    reset(&old);set_bit(BR_FDB_STICKY,&entry.flags);
    br_fdb_update(&br,&new,addr,0,0);
    assert(entry.dst==&old && entry.updated==jiffies && !begins && !ends && !deletes);
    puts("PASS: actual br_fdb_update, 3 PRE failures + success + same-port + sticky");
    return 0;
}
'''
test = prefix + function(modified,'static bool __fdb_mark_active(') + '\n' + function(modified,'void br_fdb_update(') + suffix
(root/'fdb_roam_test.c').write_text(test)
subprocess.run(['cc','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(root/'fdb_roam_test.c'),'-o',str(root/'fdb_roam_test')],check=True)
result=subprocess.run([str(root/'fdb_roam_test')],check=True,capture_output=True,text=True)
print(result.stdout,end='')
(root/'fdb-roam-result.json').write_text(json.dumps(dict(passed=True,cases=6,source_sha256=hashlib.sha256(original.encode()).hexdigest(),modified_sha256=hashlib.sha256(modified.encode()).hexdigest(),checks=['PRE failure preserves entire FDB record and emits no notifications','successful PRE precedes DEL notification and move','begin/end balance on success/failure','same-port and sticky updates retain original behavior'],sanitizers=['address','undefined']),indent=2)+'\n')
