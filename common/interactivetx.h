#ifndef LIGHTNING_INTERACTIVETX_INTERACTIVETX_H
#define LIGHTNING_INTERACTIVETX_INTERACTIVETX_H

#include <common/tx_roles.h>
#include <ccan/short_types/short_types.h>
#include <common/channel_id.h>

struct wally_psbt;
struct per_peer_state;

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

	/* Returns a PSBT with at least once change to the transaction as seen
	 * in ictx->current_psbt. If more than one change is returned, only 
	 * the *first* change will be utilized for a given cycle.
	 *
	 * If no more changes are demanded, return NULL or return current_psbt
	 * unchanged to signal completion.
	 */
	struct wally_psbt *(*next_update)(struct interactivetx_context *ictx);

	/* Set this to the intial psbt. If NULL will be filled with an empty
	 * psbt.
	 *
	 * Between next_update rounds it will be updated with one local change
	 * (if any) and one remote change (if any).
	 */
	struct wally_psbt *current_psbt;

	/* Optional field for storing your side's desired psbt state, to be
	 * used inside 'next_update'.
	 */
	struct wally_psbt *desired_psbt;
};

/* Blocks the thread until both peers are happy with the state of the
 * transaction or some kind of error / validation failure occurs.
 * 
 * Returns NULL on success or a description of the error on failure.
 */
char *process_interactivetx_updates(struct interactivetx_context *ictx);

#endif /* LIGHTNING_INTERACTIVETX_INTERACTIVETX_H */
