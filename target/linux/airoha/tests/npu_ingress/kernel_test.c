#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/string.h>
#include <linux/types.h>
#include "airoha_npu_ingress.h"

int airoha_npu_ingress_kernel_check(struct airoha_ct_pon_ifc_owner *owner,
				  const struct airoha_ct_pon_ifc_io *io,
				  const unsigned int short_lut[2], bool restore);

int airoha_npu_ingress_kernel_check(struct airoha_ct_pon_ifc_owner *owner,
				  const struct airoha_ct_pon_ifc_io *io,
				  const unsigned int short_lut[2], bool restore)
{
	return restore ? airoha_npu_ingress_restore(owner, io) :
			 airoha_npu_ingress_prepare(owner, io, short_lut);
}
