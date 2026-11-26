from pathlib import Path
import subprocess,json
r=Path(__file__).resolve().parent;src=(r/'candidate/drivers/net/ethernet/airoha/airoha_npu.c').read_text();a=src.index('static int airoha_npu_ct_pair_cmd(');z=src.index('static void airoha_npu_wlan_short_guard_clear',a)
pre=r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16,__le16;typedef uint32_t u32,__le32;typedef uint64_t __le64;typedef int32_t s32;
#define cpu_to_le16(x) ((u16)(x))
#define cpu_to_le32(x) ((u32)(x))
#define le32_to_cpu(x) ((u32)(x))
#undef static_assert
#define static_assert(x) _Static_assert(x,#x)
#include "pair_abi.inc"
#define NPU_OP_SET 1
#define NPU_FUNC_WIFI 0
struct device{void*of_node;};struct airoha_npu{struct device*dev;};
static bool ready,ram,full;static int transport_error,status,corrupt;static u32 caps;static unsigned sends;
static bool airoha_npu_wlan_short_guard_ready(struct airoha_npu*n){assert(n);return ready;}
static bool of_property_read_bool(void*n,const char*s){assert(n);if(!strcmp(s,"airoha,connac2-rebuilt-ram-lab"))return ram;assert(!strcmp(s,"airoha,connac2-ordinary-full-test"));return full;}
static int __airoha_npu_send_msg(struct airoha_npu*n,int fn,void*in,size_t ilen,void*out,size_t olen){
 assert(n&&fn==0&&ilen==72&&olen==64);u32*h=in;assert(h[0]==16&&h[1]==34);struct airoha_ct_pair_msg*m=(void*)(h+2);assert(m->magic==0x43545031&&m->abi==3&&(s32)m->status==-EINPROGRESS&&!m->caps);sends++;if(transport_error)return transport_error;memcpy(out,m,64);struct airoha_ct_pair_msg*reply=out;reply->status=status;reply->caps=caps;if(corrupt>=0)((u8*)out)[corrupt]^=1;return 0;
}
'''
main=r'''
int main(void){struct device d={.of_node=(void*)1};struct airoha_npu n={.dev=&d};unsigned cases=0;
 for(int b=0;b<56;b++){struct airoha_ct_pair_msg m={.op=1,.token=7,.src_wcid=8,.dst_wcid=9,.src_epoch=1,.dst_epoch=2};ready=ram=true;transport_error=status=0;caps=63;corrupt=b;sends=0;assert(airoha_npu_ct_pair_cmd(&n,&m)==-EPROTO&&sends==1);cases++;}
 for(int mode=0;mode<15;mode++){struct airoha_ct_pair_msg m={.op=1,.token=7};ready=ram=true;transport_error=status=0;caps=63;corrupt=-1;sends=0;int expected=0;
 switch(mode){case 1:ready=false;expected=-EOPNOTSUPP;break;case 2:ram=false;expected=-EOPNOTSUPP;break;case 3:transport_error=-ETIMEDOUT;expected=-ETIMEDOUT;break;case 4:caps=3;expected=-EPROTO;break;case 5:caps=5;expected=-EPROTO;break;case 6:caps=6;expected=-EPROTO;break;case 7:status=1;expected=-EPROTO;break;case 8:status=-EAGAIN;expected=-EAGAIN;break;case 9:status=-EINPROGRESS;expected=-EINPROGRESS;break;case 10:status=-EAGAIN;caps=0;expected=-EAGAIN;break;case 11:status=0;caps=0;expected=-EPROTO;break;case 12:caps=7;expected=-EPROTO;break;case 13:caps=15;expected=-EPROTO;break;case 14:caps=31;expected=-EPROTO;break;}
 assert(airoha_npu_ct_pair_cmd(&n,&m)==expected);assert(sends==!(mode==1||mode==2));if(!mode)assert(m.magic==0x43545031&&m.caps==63&&m.status==0);cases++;}
 struct airoha_ct_pair_msg m={.op=1,.token=7};ram=false;full=ready=true;transport_error=status=0;caps=63;corrupt=-1;sends=0;assert(!airoha_npu_ct_pair_cmd(&n,&m)&&sends==1);cases++;
 printf("PASS %u actual mailbox wrapper ABI echo, caps, status and transport cases\n",cases);}
'''
(r/'build/verify_wrapper.c').write_text(pre+src[a:z]+main)
subprocess.run(['clang','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(r/'build'),str(r/'build/verify_wrapper.c'),'-o',str(r/'build/verify_wrapper')],check=True)
p=subprocess.run([str(r/'build/verify_wrapper')],capture_output=True,text=True,check=True);print(p.stdout)
(r/'build/wrapper-verification.json').write_text(json.dumps({'passed':True,'result':p.stdout,'sanitizers':['address','undefined']},indent=2)+'\n')
