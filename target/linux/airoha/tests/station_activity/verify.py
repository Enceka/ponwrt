#!/usr/bin/env python3
"""Exercise extracted station RX activity code with sanitizer and mutation checks."""
from pathlib import Path
import argparse,hashlib,json,os,re,resource,subprocess
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mac80211-tree',type=Path,required=True)
parser.add_argument('--mt76-tree',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
root=args.output.resolve();root.mkdir(parents=True,exist_ok=False)
mac80211=args.mac80211_tree.resolve();mt76=args.mt76_tree.resolve()
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def function(path,name):
 text=path.read_text();m=re.search(r'(?:static )?(?:bool|void|unsigned long|u32)\s+'+name+r'\([^;]+?\)\n\{',text);assert m,name
 depth=0
 for pos in range(text.index('{',m.start()),len(text)):
  if text[pos]=='{':depth+=1
  if text[pos]=='}':
   depth-=1
   if depth==0:return text[m.start():pos+1]
 raise RuntimeError(name)
mac=mt76/'mt7915/mac.c'; main=mt76/'mt7915/main.c';sta=mac80211/'net/mac80211/sta_info.c'
preamble=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <pthread.h>
#include <sched.h>
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
#define IEEE80211_NUM_ACS 4
#define IEEE80211_MLD_MAX_NUM_LINKS 16
#define MT7916_CT_MAX_WCID 150
#define U32_MAX UINT32_MAX
#define HZ 100
#define MT76_STATE_RUNNING 0
#define MT76_RESET 1
#define MT76_REMOVED 2
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define time_after(a,b) ((long)((b)-(a))<0)
#define time_before(a,b) time_after(b,a)
#define WARN_ON_ONCE(v) (v)
#define EXPORT_SYMBOL_GPL(v)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define rcu_dereference(p) (p)
#define wiphy_dereference(a,b) (b)
static unsigned long jiffies;
static _Thread_local int rcu_depth;
static _Thread_local int spin_depth;
static void rcu_read_lock(void){rcu_depth++;}
static void rcu_read_unlock(void){assert(rcu_depth);rcu_depth--;}
static void spin_lock_bh(pthread_mutex_t *lock){assert(!spin_depth);pthread_mutex_lock(lock);spin_depth++;}
static void spin_unlock_bh(pthread_mutex_t *lock){assert(spin_depth);spin_depth--;pthread_mutex_unlock(lock);}
#define lockdep_assert_held(p) do { (void)(p); } while(0)
static bool test_bit(unsigned int bit,unsigned long *v){return !!(*v&(1UL<<bit));}
struct ieee80211_sta { unsigned int id; };
struct ieee80211_sta_rx_stats { unsigned long last_rx; };
struct link_sta_info { struct ieee80211_sta_rx_stats rx_stats; unsigned long last_rx_hw; struct {unsigned long last_ack;} status_stats; };
struct sta_info { struct ieee80211_sta sta; struct link_sta_info deflink; struct link_sta_info *link[16]; void *local; };
static struct ieee80211_sta_rx_stats *sta_get_last_rx_stats(struct sta_info *sta,int id){return &(id<0?&sta->deflink:sta->link[id])->rx_stats;}
'''
lastactive=function(sta,'ieee80211_sta_last_active').replace('sta->local->hw.wiphy','NULL')
body=preamble+'\n'+function(sta,'ieee80211_sta_register_rx_activity')+'\n'+lastactive+r'''
struct mt76_phy { unsigned long state; unsigned int band_idx; };
struct mt76_wcid { unsigned int phy_idx; unsigned int idx; struct ieee80211_sta *sta; };
struct mt7915_sta { struct mt76_wcid wcid; bool ct_authorized; u32 ct_epoch; u32 ct_rx_activity_epoch; u32 ct_rx_airtime[4]; };
struct mt76_dev { pthread_mutex_t sta_poll_lock; int mutex; struct mt76_wcid *wcid[152]; };
struct mt7915_dev { struct mt76_dev mt76; struct mt76_phy mphy; bool enabled; unsigned int bank; u32 hw[152][4]; unsigned long reads; };
struct mt7915_phy { struct mt76_phy *mt76; struct mt7915_dev *dev; unsigned long ct_rx_activity_next; };
static bool mt7915_ct_wed_active(struct mt7915_dev *dev){return dev->enabled;}
static struct mt76_wcid *get_wcid(struct mt7915_dev *dev,int idx){assert(rcu_depth);return dev->mt76.wcid[idx];}
#define mt76_wcid_ptr(d,i) get_wcid(d,i)
static struct ieee80211_sta *wcid_to_sta(struct mt76_wcid *wcid){assert(rcu_depth);return wcid->sta;}
#define MT_WTBLON_TOP_WDUCR 1
#define MT_WTBLON_TOP_WDUCR_GROUP 7
#define FIELD_PREP(mask,val) (val)
#define MT_WTBL_LMAC_OFFS(idx,dw) (((idx)&127)*0x100+(dw)*4)
static void mt76_wr(struct mt7915_dev *dev,u32 reg,u32 value){assert(spin_depth);assert(reg==1);dev->bank=value;sched_yield();}
static u32 mt76_rr(struct mt7915_dev *dev,u32 addr){unsigned int idx=dev->bank*128+addr/256;unsigned int dw=(addr%256)/4;assert(spin_depth);assert(idx<152);assert(dw>=21&&dw<=27&&(dw&1));dev->reads++;sched_yield();return dev->hw[idx][(dw-21)/2];}
'''+function(mac,'mt7915_mac_wtbl_lmac_addr')+'\n'+function(mac,'mt7915_ct_rx_activity_sample')+'\n'+function(mac,'mt7915_ct_rx_activity_poll')+'\n'+function(main,'mt7915_ct_publish_sta')+r'''
static struct mt7915_dev dev;
static struct mt7915_sta stations[152];
static struct sta_info macstas[152];
static struct mt76_phy radios[2];
static struct mt7915_phy phys[2];
static unsigned int tests;
#define CHECK(v) do {assert(v);tests++;}while(0)
static void tick(unsigned long now){jiffies=now;for(int b=0;b<2;b++)mt7915_ct_rx_activity_poll(&phys[b]);}
static void *bank_writer(void *unused){(void)unused;for(int i=0;i<2000;i++){spin_lock_bh(&dev.mt76.sta_poll_lock);mt7915_mac_wtbl_lmac_addr(&dev,128+(i%23),30);spin_unlock_bh(&dev.mt76.sta_poll_lock);}return NULL;}
int main(void){
 struct mt7915_sta sample={0};u32 v[4]={10,20,30,40};
 CHECK(!mt7915_ct_rx_activity_sample(&sample,1,v));
 CHECK(!mt7915_ct_rx_activity_sample(&sample,1,v));
 v[1]++;CHECK(mt7915_ct_rx_activity_sample(&sample,1,v));
 memset(v,0,sizeof(v));CHECK(!mt7915_ct_rx_activity_sample(&sample,1,v));
 v[3]=1;CHECK(mt7915_ct_rx_activity_sample(&sample,1,v));
 v[0]=100;CHECK(!mt7915_ct_rx_activity_sample(&sample,2,v));
 v[1]=U32_MAX;CHECK(!mt7915_ct_rx_activity_sample(&sample,2,v));
 CHECK(sample.ct_rx_activity_epoch==0);v[1]=200;
 CHECK(!mt7915_ct_rx_activity_sample(&sample,2,v));
 sample.ct_rx_airtime[0]=U32_MAX-2;v[0]=5;CHECK(mt7915_ct_rx_activity_sample(&sample,2,v));
 struct sta_info s={0};s.deflink.rx_stats.last_rx=10;s.deflink.status_stats.last_ack=20;
 jiffies=30;ieee80211_sta_register_rx_activity(&s.sta,-1);CHECK(ieee80211_sta_last_active(&s,-1)==30);CHECK(s.deflink.rx_stats.last_rx==10);
 s.deflink.rx_stats.last_rx=40;CHECK(ieee80211_sta_last_active(&s,-1)==40);
 s.deflink.status_stats.last_ack=50;CHECK(ieee80211_sta_last_active(&s,-1)==50);
 s.deflink.status_stats.last_ack=0;s.deflink.rx_stats.last_rx=~0UL-5;jiffies=4;ieee80211_sta_register_rx_activity(&s.sta,-1);CHECK(ieee80211_sta_last_active(&s,-1)==4);
 struct link_sta_info link={0};s.link[15]=&link;jiffies=25;ieee80211_sta_register_rx_activity(&s.sta,15);CHECK(ieee80211_sta_last_active(&s,15)==25);
 ieee80211_sta_register_rx_activity(&s.sta,0);ieee80211_sta_register_rx_activity(&s.sta,16);ieee80211_sta_register_rx_activity(&s.sta,-2);CHECK(link.last_rx_hw==25);
 pthread_mutex_init(&dev.mt76.sta_poll_lock,NULL);dev.enabled=true;
 for(int b=0;b<2;b++){radios[b].state=1;radios[b].band_idx=b;phys[b].mt76=&radios[b];phys[b].dev=&dev;}
 for(int i=1;i<=151;i++){struct mt7915_sta *m=&stations[i];m->wcid.idx=i;m->wcid.phy_idx=i%2;m->wcid.sta=&macstas[i].sta;m->ct_authorized=true;m->ct_epoch=1;dev.mt76.wcid[i]=&m->wcid;dev.hw[i][0]=i;macstas[i].deflink.rx_stats.last_rx=1;}
 tick(100);CHECK(dev.reads==150*4);for(int i=1;i<=151;i++)CHECK(macstas[i].deflink.last_rx_hw==0);
 tick(199);CHECK(dev.reads==150*4);
 for(int i=1;i<=151;i++)dev.hw[i][0]++;
 tick(200);for(int i=1;i<=150;i++)CHECK(macstas[i].deflink.last_rx_hw==200);CHECK(macstas[151].deflink.last_rx_hw==0);
 tick(300);for(int i=1;i<=150;i++)CHECK(macstas[i].deflink.last_rx_hw==200);
 for(int i=1;i<=150;i++)memset(dev.hw[i],0,sizeof(dev.hw[i]));
 tick(400);for(int i=1;i<=150;i++)CHECK(macstas[i].deflink.last_rx_hw==200);
 dev.hw[128][3]=4;tick(500);CHECK(macstas[128].deflink.last_rx_hw==500);CHECK(macstas[127].deflink.last_rx_hw==200);CHECK(macstas[150].deflink.last_rx_hw==200);
 mt7915_ct_publish_sta(&dev,&stations[128],false,0);dev.hw[128][3]++;tick(600);CHECK(macstas[128].deflink.last_rx_hw==500);CHECK(stations[128].ct_rx_activity_epoch==0);
 mt7915_ct_publish_sta(&dev,&stations[128],true,2);tick(700);CHECK(macstas[128].deflink.last_rx_hw==500);dev.hw[128][3]++;tick(800);CHECK(macstas[128].deflink.last_rx_hw==800);
 dev.enabled=false;unsigned long read_before=dev.reads;tick(900);CHECK(dev.reads==read_before);CHECK(stations[128].ct_rx_activity_epoch==0);
 dev.enabled=true;dev.hw[128][3]++;tick(1000);CHECK(macstas[128].deflink.last_rx_hw==800);dev.hw[128][3]++;tick(1100);CHECK(macstas[128].deflink.last_rx_hw==1100);
 radios[0].state|=1<<MT76_RESET;read_before=dev.reads;tick(1200);CHECK(dev.reads-read_before==75*4);CHECK(stations[128].ct_rx_activity_epoch==0);radios[0].state&=~(1<<MT76_RESET);
 dev.mt76.wcid[127]=NULL;tick(1300);CHECK(macstas[127].deflink.last_rx_hw==200);struct mt7915_sta replacement={0};struct sta_info replace_sta={0};replacement.wcid.idx=127;replacement.wcid.phy_idx=1;replacement.wcid.sta=&replace_sta.sta;replacement.ct_authorized=true;replacement.ct_epoch=1;dev.mt76.wcid[127]=&replacement.wcid;dev.hw[127][0]=77;tick(1400);CHECK(replace_sta.deflink.last_rx_hw==0);dev.hw[127][0]++;tick(1500);CHECK(replace_sta.deflink.last_rx_hw==1500);
 for(int i=1;i<=150;i++)for(int ac=0;ac<4;ac++)dev.hw[i][ac]=i*100+ac;
 tick(1600);unsigned long snapshots[152];for(int i=1;i<=150;i++)snapshots[i]=macstas[i].deflink.last_rx_hw;
 pthread_t writer;pthread_create(&writer,NULL,bank_writer,NULL);
 for(int k=17;k<80;k++)tick(k*100);
 pthread_join(writer,NULL);
 for(int i=1;i<=150;i++)CHECK(macstas[i].deflink.last_rx_hw==snapshots[i]);CHECK(replace_sta.deflink.last_rx_hw==1600);
 CHECK(!rcu_depth&&!spin_depth);
 printf("{\"passed\":true,\"assertions\":%u,\"wtbl_reads\":%lu,\"scope\":\"extracted production helper, last_active, sampler and poll; all WCIDs; threaded bank competition\"}\n",tests,dev.reads);
 return 0;
}
'''
compiler=os.environ.get('CC','cc')
flags=['-std=c11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-pthread','-fsanitize=address,undefined','-g']
def execute(name,source,expect_pass):
    c=root/(name+'.c');binary=root/name;c.write_text(source)
    subprocess.run([compiler,*flags,'-o',str(binary),str(c)],check=True)
    process=subprocess.run([str(binary)],capture_output=True,text=True)
    (root/(name+'.log')).write_text(process.stdout+process.stderr)
    assert (process.returncode==0)==expect_pass,(name,process.stdout,process.stderr)
    return process
passed=execute('selftest',body,True)
report=json.loads(passed.stdout)
assert report['assertions']==789,report
mutations=[
 ('missing-helper-update','WRITE_ONCE(link->last_rx_hw, jiffies);','(void)link;'),
 ('missing-hardware-time-merge','if (last_rx_hw && time_after(last_rx_hw, last_rx))','if (0 && last_rx_hw && time_after(last_rx_hw, last_rx))'),
 ('wcid-128-and-above-omitted','idx <= MT7916_CT_MAX_WCID','idx < 128'),
 ('authorization-ignored','if (!enabled || !epoch || !READ_ONCE(msta->ct_authorized))','if (!enabled)'),
 ('baseline-not-reset-on-epoch','if (msta->ct_rx_activity_epoch == epoch)','if (true)'),
 ('counter-clear-counted-as-rx','if (airtime[i] && airtime[i] != msta->ct_rx_airtime[i])','if (airtime[i] != msta->ct_rx_airtime[i])'),
 ('shared-bank-unlocked','spin_lock_bh(&dev->mt76.sta_poll_lock);\n\t\tepoch','/* omitted lock */\n\t\tepoch'),
]
report['negative_controls']=[]
for name,old,new in mutations:
    assert body.count(old)==1,(name,body.count(old))
    process=execute(name,body.replace(old,new),False)
    report['negative_controls'].append({'name':name,'compiled':True,'detected':True,'returncode':process.returncode})
# Check the full integration around the extracted functions.
source_paths=[mac,main,mt76/'mt7915/mcu.c',mt76/'mt7915/mt7915.h',sta,mac80211/'net/mac80211/sta_info.h',mac80211/'include/net/mac80211.h']
mac_text=mac.read_text();main_text=main.read_text()
worker=mac_text[mac_text.index('void mt7915_mac_work('):]
assert worker.index('mutex_lock(&mphy->dev->mutex)')<worker.index('mt7915_ct_rx_activity_poll(phy)')<worker.index('mutex_unlock(&mphy->dev->mutex)')
assert 'WRITE_ONCE(msta->ct_epoch, epoch)' not in main_text.replace(function(main,'mt7915_ct_publish_sta'),'')
assert 'WRITE_ONCE(msta->ct_authorized,' not in main_text.replace(function(main,'mt7915_ct_publish_sta'),'')
assert 'EXPORT_SYMBOL_GPL(ieee80211_sta_register_rx_activity);' in sta.read_text()
assert 'unsigned long last_rx_hw;' in (mac80211/'net/mac80211/sta_info.h').read_text()
locked_calls=0
for path in [mac,main,mt76/'mt7915/mcu.c']:
    text=path.read_text()
    # An early unlock followed by continue exits this loop iteration.
    text=re.sub(r'if \([^;\n{}]*\) \{[^{}]*spin_unlock_bh\(&dev->mt76.sta_poll_lock\);\s*continue;\s*\}', '', text)
    for match in re.finditer(r'addr = mt7915_mac_wtbl_lmac_addr\(',text):
        preceding=text[:match.start()]
        assert preceding.rfind('spin_lock_bh(&dev->mt76.sta_poll_lock);')>preceding.rfind('spin_unlock_bh(&dev->mt76.sta_poll_lock);'),(path,match.start())
        tail=text[match.start():];unlock=tail.index('spin_unlock_bh(&dev->mt76.sta_poll_lock);')
        for forbidden in ('mt7915_mcu_', 'mt76_npu_', 'mutex_lock(', 'msleep(', 'usleep_range('):
            assert forbidden not in tail[:unlock],(path,forbidden)
        locked_calls+=1
assert locked_calls==6,locked_calls
report['locked_bank_calls']=locked_calls
report['source_sha256']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths}
report['sanitizers']=['address','undefined']
(root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS 789 station activity assertions, 7 runtime negative controls, 6 locked WTBL bank call sites; '+str(root/'report.json'))
