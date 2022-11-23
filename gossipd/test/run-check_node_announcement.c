#include "config.h"
#include "../gossip_generation.c"
#include <common/blinding.h>
#include <common/channel_type.h>
#include <common/ecdh.h>
#include <common/json_stream.h>
#include <common/onionreply.h>
#include <common/setup.h>
#include <stdio.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for blinding_hash_e_and_ss */
void blinding_hash_e_and_ss(const struct pubkey *e UNNEEDED,
			    const struct secret *ss UNNEEDED,
			    struct sha256 *sha UNNEEDED)
{ fprintf(stderr, "blinding_hash_e_and_ss called!\n"); abort(); }
/* Generated stub for blinding_next_privkey */
bool blinding_next_privkey(const struct privkey *e UNNEEDED,
			   const struct sha256 *h UNNEEDED,
			   struct privkey *next UNNEEDED)
{ fprintf(stderr, "blinding_next_privkey called!\n"); abort(); }
/* Generated stub for blinding_next_pubkey */
bool blinding_next_pubkey(const struct pubkey *pk UNNEEDED,
			  const struct sha256 *h UNNEEDED,
			  struct pubkey *next UNNEEDED)
{ fprintf(stderr, "blinding_next_pubkey called!\n"); abort(); }
/* Generated stub for daemon_conn_send */
void daemon_conn_send(struct daemon_conn *dc UNNEEDED, const u8 *msg UNNEEDED)
{ fprintf(stderr, "daemon_conn_send called!\n"); abort(); }
/* Generated stub for ecdh */
void ecdh(const struct pubkey *point UNNEEDED, struct secret *ss UNNEEDED)
{ fprintf(stderr, "ecdh called!\n"); abort(); }
/* Generated stub for find_peer */
struct peer *find_peer(struct daemon *daemon UNNEEDED, const struct node_id *id UNNEEDED)
{ fprintf(stderr, "find_peer called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_local_channel_update */
bool fromwire_gossipd_local_channel_update(const void *p UNNEEDED, struct node_id *id UNNEEDED, struct short_channel_id *short_channel_id UNNEEDED, bool *disable UNNEEDED, bool *splicing UNNEEDED, u16 *cltv_expiry_delta UNNEEDED, struct amount_msat *htlc_minimum_msat UNNEEDED, u32 *fee_base_msat UNNEEDED, u32 *fee_proportional_millionths UNNEEDED, struct amount_msat *htlc_maximum_msat UNNEEDED, bool *public UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_local_channel_update called!\n"); abort(); }
/* Generated stub for fromwire_gossipd_used_local_channel_update */
bool fromwire_gossipd_used_local_channel_update(const void *p UNNEEDED, struct short_channel_id *scid UNNEEDED)
{ fprintf(stderr, "fromwire_gossipd_used_local_channel_update called!\n"); abort(); }
/* Generated stub for fromwire_hsmd_cupdate_sig_reply */
bool fromwire_hsmd_cupdate_sig_reply(const tal_t *ctx UNNEEDED, const void *p UNNEEDED, u8 **cu UNNEEDED)
{ fprintf(stderr, "fromwire_hsmd_cupdate_sig_reply called!\n"); abort(); }
/* Generated stub for fromwire_hsmd_node_announcement_sig_reply */
bool fromwire_hsmd_node_announcement_sig_reply(const void *p UNNEEDED, secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "fromwire_hsmd_node_announcement_sig_reply called!\n"); abort(); }
/* Generated stub for get_node */
struct node *get_node(struct routing_state *rstate UNNEEDED,
		      const struct node_id *id UNNEEDED)
{ fprintf(stderr, "get_node called!\n"); abort(); }
/* Generated stub for gossip_time_now */
struct timeabs gossip_time_now(const struct routing_state *rstate UNNEEDED)
{ fprintf(stderr, "gossip_time_now called!\n"); abort(); }
/* Generated stub for handle_channel_update */
u8 *handle_channel_update(struct routing_state *rstate UNNEEDED, const u8 *update TAKES UNNEEDED,
			  struct peer *peer UNNEEDED,
			  struct short_channel_id *unknown_scid UNNEEDED,
			  bool force UNNEEDED)
{ fprintf(stderr, "handle_channel_update called!\n"); abort(); }
/* Generated stub for handle_node_announcement */
u8 *handle_node_announcement(struct routing_state *rstate UNNEEDED, const u8 *node UNNEEDED,
			     struct peer *peer UNNEEDED, bool *was_unknown UNNEEDED)
{ fprintf(stderr, "handle_node_announcement called!\n"); abort(); }
/* Generated stub for master_badmsg */
void master_badmsg(u32 type_expected UNNEEDED, const u8 *msg)
{ fprintf(stderr, "master_badmsg called!\n"); abort(); }
/* Generated stub for new_onionreply */
struct onionreply *new_onionreply(const tal_t *ctx UNNEEDED, const u8 *contents TAKES UNNEEDED)
{ fprintf(stderr, "new_onionreply called!\n"); abort(); }
/* Generated stub for new_reltimer_ */
struct oneshot *new_reltimer_(struct timers *timers UNNEEDED,
			      const tal_t *ctx UNNEEDED,
			      struct timerel expire UNNEEDED,
			      void (*cb)(void *) UNNEEDED, void *arg UNNEEDED)
{ fprintf(stderr, "new_reltimer_ called!\n"); abort(); }
/* Generated stub for queue_peer_msg */
void queue_peer_msg(struct peer *peer UNNEEDED, const u8 *msg TAKES UNNEEDED)
{ fprintf(stderr, "queue_peer_msg called!\n"); abort(); }
/* Generated stub for status_failed */
void status_failed(enum status_failreason code UNNEEDED,
		   const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "status_failed called!\n"); abort(); }
/* Generated stub for status_fmt */
void status_fmt(enum log_level level UNNEEDED,
		const struct node_id *peer UNNEEDED,
		const char *fmt UNNEEDED, ...)

{ fprintf(stderr, "status_fmt called!\n"); abort(); }
/* Generated stub for towire_gossipd_got_local_channel_update */
u8 *towire_gossipd_got_local_channel_update(const tal_t *ctx UNNEEDED, const struct short_channel_id *scid UNNEEDED, const u8 *channel_update UNNEEDED)
{ fprintf(stderr, "towire_gossipd_got_local_channel_update called!\n"); abort(); }
/* Generated stub for towire_hsmd_cupdate_sig_req */
u8 *towire_hsmd_cupdate_sig_req(const tal_t *ctx UNNEEDED, const u8 *cu UNNEEDED)
{ fprintf(stderr, "towire_hsmd_cupdate_sig_req called!\n"); abort(); }
/* Generated stub for towire_hsmd_node_announcement_sig_req */
u8 *towire_hsmd_node_announcement_sig_req(const tal_t *ctx UNNEEDED, const u8 *announcement UNNEEDED)
{ fprintf(stderr, "towire_hsmd_node_announcement_sig_req called!\n"); abort(); }
/* Generated stub for wire_sync_read */
u8 *wire_sync_read(const tal_t *ctx UNNEEDED, int fd UNNEEDED)
{ fprintf(stderr, "wire_sync_read called!\n"); abort(); }
/* Generated stub for wire_sync_write */
bool wire_sync_write(int fd UNNEEDED, const void *msg TAKES UNNEEDED)
{ fprintf(stderr, "wire_sync_write called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

/* Overwriting this to return test data */
const u8 *gossip_store_get(const tal_t *ctx,
			   struct gossip_store *gs,
			   u64 offset)
{
	/* No TLV, different */
	if (offset == 0)
		return tal_hexdata(ctx, "01010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000078000000802aaa260b145790266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c035180266e453454e494f524245414d000000000000000000000000000000000000000000000000", strlen("01010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000078000000802aaa260b145790266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c035180266e453454e494f524245414d000000000000000000000000000000000000000000000000"));

	/* No TLV, same */
	if (offset == 1)
		return tal_hexdata(ctx, "01017d49b51b7d3772636c09901df78c81faa1a7f045e329366ad779ecbaf0cc07f764d8ffd3596ef6802fd0e4c5c180c74fb3dfb14aae493ed48d35a3df75c20eca00078000000802aaa260b14569022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59022d2253494c454e544152544953542d3236352d67373833393533312d6d6f646465640000", strlen("01017d49b51b7d3772636c09901df78c81faa1a7f045e329366ad779ecbaf0cc07f764d8ffd3596ef6802fd0e4c5c180c74fb3dfb14aae493ed48d35a3df75c20eca00078000000802aaa260b14569022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59022d2253494c454e544152544953542d3236352d67373833393533312d6d6f646465640000"));

	/* Same, with TLV */
	if (offset == 2)
		return tal_hexdata(ctx, "0101069628d227649cc2823d94647ad08ea34ad24e7eea95b7a0249bc83e73efefa6072cab1841f0ef3e6d7f4c4140b7b1b13049eb0d85941d7d7bd30c921bfd550300078000000802aaa260b1496f0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c035180266e453454e494f524245414d000000000000000000000000000000000000000000000000010c0014000003e80096001607d0", strlen("0101069628d227649cc2823d94647ad08ea34ad24e7eea95b7a0249bc83e73efefa6072cab1841f0ef3e6d7f4c4140b7b1b13049eb0d85941d7d7bd30c921bfd550300078000000802aaa260b1496f0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c035180266e453454e494f524245414d000000000000000000000000000000000000000000000000010c0014000003e80096001607d0"));

	return NULL;
}

int main(int argc, char *argv[])
{
	struct node node;
	bool only_missing_tlv;
	u8 *ann;

	common_setup(argv[0]);

	/* No TLV checks */
	node.bcast.index = 1;
	ann = tal_hexdata(tmpctx, "01017d49b51b7d3772636c09901df78c81faa1a7f045e329366ad779ecbaf0cc07f764d8ffd3596ef6802fd0e4c5c180c74fb3dfb14aae493ed48d35a3df75c20eca00078000000802aaa260b14569022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59022d2253494c454e544152544953542d3236352d67373833393533312d6d6f646465640000", strlen("01017d49b51b7d3772636c09901df78c81faa1a7f045e329366ad779ecbaf0cc07f764d8ffd3596ef6802fd0e4c5c180c74fb3dfb14aae493ed48d35a3df75c20eca00078000000802aaa260b14569022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59022d2253494c454e544152544953542d3236352d67373833393533312d6d6f646465640000"));
	assert(!nannounce_different(NULL, &node, ann, &only_missing_tlv));
	assert(!only_missing_tlv);

	node.bcast.index = 0;
	assert(nannounce_different(NULL, &node, ann, &only_missing_tlv));
	assert(!only_missing_tlv);

	/* TLV checks */
	ann = tal_hexdata(tmpctx, "0101069628d227649cc2823d94647ad08ea34ad24e7eea95b7a0249bc83e73efefa6072cab1841f0ef3e6d7f4c4140b7b1b13049eb0d85941d7d7bd30c921bfd550300078000000802aaa260b1496f0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c035180266e453454e494f524245414d000000000000000000000000000000000000000000000000010c0014000003e80096001607d0", strlen("0101069628d227649cc2823d94647ad08ea34ad24e7eea95b7a0249bc83e73efefa6072cab1841f0ef3e6d7f4c4140b7b1b13049eb0d85941d7d7bd30c921bfd550300078000000802aaa260b1496f0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c035180266e453454e494f524245414d000000000000000000000000000000000000000000000000010c0014000003e80096001607d0"));

	node.bcast.index = 2;
	assert(!nannounce_different(NULL, &node, ann, &only_missing_tlv));
	assert(!only_missing_tlv);

	/* Tweak the last, check that it fails */
	node.bcast.index = 2;
	ann[tal_count(ann) - 1]++;
	assert(nannounce_different(NULL, &node, ann, &only_missing_tlv));
	assert(only_missing_tlv);

	common_shutdown();
	return 0;
}
