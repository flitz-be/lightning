#ifndef LIGHTNING_INTERACTIVE_TX_STATE_H
#define LIGHTNING_INTERACTIVE_TX_STATE_H

#include <bitcoin/script.h>
#include <bitcoin/psbt.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/billboard.h>
#include <common/blockheight_states.h>
#include <common/channel_type.h>
#include <common/crypto_sync.h>
#include <common/gossip_rcvd_filter.h>
#include <common/gossip_store.h>
#include <common/initial_channel.h>
#include <common/lease_rates.h>
#include <common/memleak.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/psbt_internal.h>
#include <common/psbt_open.h>
#include <common/read_peer_msg.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>

/* tx_add_input, tx_add_output, tx_rm_input, tx_rm_output */
#define NUM_TX_MSGS (TX_RM_OUTPUT + 1)
enum tx_msgs {
	TX_ADD_INPUT,
	TX_ADD_OUTPUT,
	TX_RM_INPUT,
	TX_RM_OUTPUT,
};

/*
 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
 * The maximum inputs and outputs are capped at 252. This effectively fixes
 * the byte size of the input and output counts on the transaction to one (1).
 */
#define MAX_TX_MSG_RCVD (1 << 12)

/* State for a 'new' funding transaction. There should be one
 * for every new funding transaction attempt */
struct inprog_tx_state {
	/* Funding and feerate: set by opening peer. */
	struct amount_sat opener_funding;
	struct amount_sat accepter_funding;
	u32 tx_locktime;
	u32 feerate_per_kw_funding;

	struct bitcoin_outpoint funding;

	/* This is a cluster of fields in open_channel and accept_channel which
	 * indicate the restrictions each side places on the channel. */
	struct channel_config localconf, remoteconf;

	/* PSBT of the funding tx */
	struct wally_psbt *psbt;

	/* Set of pending changes to send to peer */
	struct psbt_changeset *changeset;

	/* The serial_id of the funding output */
	u64 funding_serial;

	/* Track how many of each tx collab msg we receive */
	u16 tx_msg_count[NUM_TX_MSGS];

	/* Have we gotten the peer's tx-sigs yet? */
	bool remote_funding_sigs_rcvd;
};

/* Global state structure.  This is only for the one specific peer and channel */
struct inprog_state {
	struct per_peer_state *pps;

	/* Features they offered */
	u8 *their_features;

	/* Constraints on a channel they open. */
	u32 minimum_depth;
	struct amount_msat min_effective_htlc_capacity;

	/* Limits on what remote config we accept. */
	u32 max_to_self_delay;

	/* These are the points lightningd told us to use when accepting or
	 * opening a channel. */
	struct basepoints our_points;
	struct pubkey our_funding_pubkey;
	struct pubkey their_funding_pubkey;

	/* Information we need between funding_start and funding_complete */
	struct basepoints their_points;

	/* hsmd gives us our first per-commitment point, and peer tells us
	 * theirs */
	struct pubkey first_per_commitment_point[NUM_SIDES];

	struct channel_id channel_id;
};

bool send_next(struct inprog_state *state,
	       struct inprog_tx_state *tx_state,
	       struct wally_psbt **psbt,
	       struct wally_psbt *(*fetch_psbt_changes)(void *state_ptr,
							void *tx_state_ptr,
							const struct wally_psbt *psbt));

// WIRE_TX_ADD_INPUT
// WIRE_TX_REMOVE_INPUT
// WIRE_TX_ADD_OUTPUT
// WIRE_TX_REMOVE_OUTPUT
// Returns a human description of error on failure, NULL on success
char *run_tx_interactive(struct inprog_state *state,
			       struct inprog_tx_state *tx_state,
			       struct wally_psbt **orig_psbt,
			       enum tx_role our_role,
			       struct wally_psbt *(*fetch_psbt_changes)(void *state_ptr,
									void *tx_state_ptr,
									const struct wally_psbt *psbt)
			       );

#endif /* LIGHTNING_INTERACTIVE_TX_STATE_H */
