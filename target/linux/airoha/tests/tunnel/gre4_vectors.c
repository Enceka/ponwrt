#include "airoha_ct_gre4.h"

int gre4_row(struct airoha_ct_gre4_row *row, bool encap, const u8 *header, size_t len);
int gre4_link(struct airoha_foe_entry *foe, bool encap, unsigned int slot);

int gre4_row(struct airoha_ct_gre4_row *row, bool encap, const u8 *header, size_t len)
{
	return airoha_ct_gre4_row_encode(row, encap ? FLOW_ACTION_TUNNEL_ENCAP :
					 FLOW_ACTION_TUNNEL_DECAP, header, len);
}

int gre4_link(struct airoha_foe_entry *foe, bool encap, unsigned int slot)
{
	return airoha_ct_gre4_link(foe, encap ? FLOW_ACTION_TUNNEL_ENCAP :
				  FLOW_ACTION_TUNNEL_DECAP, slot);
}
