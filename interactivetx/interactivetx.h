#ifndef LIGHTNING_INTERACTIVETX_INTERACTIVETX_H
#define LIGHTNING_INTERACTIVETX_INTERACTIVETX_H

#include <common/tx_roles.h>

struct wally_psbt;
struct per_peer_state;

/* Interactive tx handles the building and updating of a transaction between
 * two peers. A PSBT is passed back and forth between two peers in steps. In
 * each step a peer can suggest a single change or signal they're done
 * updating with WIRE_TX_COMPLETE. Once two steps in a row result in
 * WIRE_TX_COMPLETE the transaction is considered complete.
 */

struct interactivetx_context {

	/* Shall return the PSBT with one incremental change to the
	 * transaction. 'ictx->current_psbt' parameter gives the current agreed
	 * upon state of the transaction being worked on.
	 */
	struct wally_psbt *(*next_update)(struct interactivetx_context *ictx);

	enum tx_role our_role;
	struct per_peer_state *pps;

	const struct wally_psbt *current_psbt;
};

/* Blocks the thread until both peers are happy with the state of the
 * transaction or some kind of error / validation failure occurs.
 * 
 * Returns NULL on success or a description of the error on failure.
 */
u8 *process_interactivetx_updates(struct interactivetx_context *ictx);

#endif /* LIGHTNING_INTERACTIVETX_INTERACTIVETX_H */
