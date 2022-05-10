#ifndef LIGHTNING_INTERACTIVETX_INTERACTIVETX_H
#define LIGHTNING_INTERACTIVETX_INTERACTIVETX_H

#include <ccan/short_types/short_types.h>
#include <common/channel_id.h>
#include <common/per_peer_state.h>
#include <common/tx_roles.h>
#include <common/utils.h>
#include <wally_psbt.h>

/* Interactive tx handles the building and updating of a transaction between
 * two peers. A PSBT is passed back and forth between two peers in steps. In
 * each step a peer can suggest a single change or signal they're done
 * updating with WIRE_TX_COMPLETE. Once two steps in a row result in
 * WIRE_TX_COMPLETE the transaction is considered complete.
 */

#define INTERACTIVETX_NUM_TX_MSGS 4

struct interactivetx_context {

	/* Users can set this to their own context */
	void *ctx;

	enum tx_role our_role;
	struct per_peer_state *pps;
	struct channel_id channel_id;

	/* Track how many of each tx collab msg we receive */
	u16 tx_msg_count[INTERACTIVETX_NUM_TX_MSGS];

	/* Returns a PSBT with at least one change to the transaction as
	 * compared to ictx->current_psbt.
	 *
	 * If set to NULL, the default implementation will simply return
	 * ictx->desired_psbt.
	 *
	 * The resulting psbt's memory is taken.
	 *
	 * If no more changes are demanded, return NULL or return current_psbt
	 * unchanged to signal completion.
	 */
	struct wally_psbt *(*next_update)(struct interactivetx_context *ictx);

	/* Set this to the intial psbt. If NULL will be filled with an empty
	 * psbt.
	 */
	struct wally_psbt *current_psbt;

	/* Optional field for storing your side's desired psbt state, to be
	 * used inside 'next_update'.
	 *
	 * If returned from next_update (the default) its memory will be stolen
	 */
	struct wally_psbt *desired_psbt STEALS;

	/* If true, process_interactivetx_updates will return when local changes
	 * are exhausted and 'tx_complete' will not be sent.
	 */
	bool pause_when_complete;

	/* Internal cached change set */
	struct psbt_changeset *change_set;
};

/* Blocks the thread until
 * 1) both peers are happy with the state of the transaction,
 * 2) we've run out of local changes and 'pause_when_complete' is true, or
 * 3) some kind of error / validation failure occurs.
 * 
 * If received_tx_complete is not NULL:
 * in -> true means we already received tx_complete in a previous round.
 * out -> true means the last message from the peer was 'tx_complete'.
 * 
 * Returns NULL on success or a description of the error on failure.
 */
char *process_interactivetx_updates(struct interactivetx_context *ictx,
				    bool *received_tx_complete);

#endif /* LIGHTNING_INTERACTIVETX_INTERACTIVETX_H */
