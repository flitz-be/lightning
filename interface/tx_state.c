#include "tx_state.h"
#include <bitcoin/chainparams.h>

static bool is_segwit_output(struct wally_tx_output *output,
			     const u8 *redeemscript)
{
	const u8 *wit_prog;
	if (tal_bytelen(redeemscript) > 0)
		wit_prog = redeemscript;
	else
		wit_prog = wally_tx_output_get_script(tmpctx, output);

	return is_p2wsh(wit_prog, NULL) || is_p2wpkh(wit_prog, NULL);
}

/* psbt_changeset_get_next - Get next message to send
 *
 * This generates the next message to send from a changeset for the
 * interactive transaction protocol.
 *
 * @ctx - allocation context of returned msg
 * @cid - channel_id for the message
 * @set - changeset to get next update from
 *
 * Returns a wire message or NULL if no changes.
 */
static u8 *psbt_changeset_get_next(const tal_t *ctx,
				   struct channel_id *cid,
				   struct psbt_changeset *set)
{
	u64 serial_id;
	u8 *msg;

	if (tal_count(set->added_ins) != 0) {
		const struct input_set *in = &set->added_ins[0];
		u8 *script;

		if (!psbt_get_serial_id(&in->input.unknowns, &serial_id))
			abort();

		const u8 *prevtx = linearize_wtx(ctx,
						 in->input.utxo);

		if (in->input.redeem_script_len)
			script = tal_dup_arr(ctx, u8,
					     in->input.redeem_script,
					     in->input.redeem_script_len, 0);
		else
			script = NULL;

		msg = towire_tx_add_input(ctx, cid, serial_id,
					  prevtx, in->tx_input.index,
					  in->tx_input.sequence,
					  script);

		tal_arr_remove(&set->added_ins, 0);
		return msg;
	}
	if (tal_count(set->rm_ins) != 0) {
		if (!psbt_get_serial_id(&set->rm_ins[0].input.unknowns,
					&serial_id))
			abort();

		msg = towire_tx_remove_input(ctx, cid, serial_id);

		tal_arr_remove(&set->rm_ins, 0);
		return msg;
	}
	if (tal_count(set->added_outs) != 0) {
		struct amount_sat sats;
		struct amount_asset asset_amt;

		const struct output_set *out = &set->added_outs[0];
		if (!psbt_get_serial_id(&out->output.unknowns, &serial_id))
			abort();

		asset_amt = wally_tx_output_get_amount(&out->tx_output);
		sats = amount_asset_to_sat(&asset_amt);
		const u8 *script = wally_tx_output_get_script(ctx,
							      &out->tx_output);

		msg = towire_tx_add_output(ctx, cid, serial_id,
					   sats.satoshis, /* Raw: wire interface */
					   script);

		tal_arr_remove(&set->added_outs, 0);
		return msg;
	}
	if (tal_count(set->rm_outs) != 0) {
		if (!psbt_get_serial_id(&set->rm_outs[0].output.unknowns,
					&serial_id))
			abort();

		msg = towire_tx_remove_output(ctx, cid, serial_id);

		/* Is this a kosher way to move the list forward? */
		tal_arr_remove(&set->rm_outs, 0);
		return msg;
	}
	return NULL;
}

static struct wally_psbt *
fetch_psbt_changes(struct inprog_state *state,
		   struct inprog_tx_state *tx_state,
		   const struct wally_psbt *psbt)
{
	u8 *msg;
	//DD char *err;
	//DD struct wally_psbt *updated_psbt;

	/* Go ask lightningd what other changes we've got */
	msg = NULL;//DD towire_dualopend_psbt_changed(NULL, &state->channel_id,
				//DD	    tx_state->funding_serial,
				//DD	    psbt);

	//DD wire_sync_write(REQ_FD, take(msg));
	//DD msg = wire_sync_read(tmpctx, REQ_FD);

	//DD if (fromwire_dualopend_fail(msg, msg, &err)) {
	//DD 	open_err_warn(state, "%s", err);
	//DD } else if (fromwire_dualopend_psbt_updated(state, msg, &updated_psbt)) {
	//DD 	return updated_psbt;
	//DD } else
	//DD 	master_badmsg(fromwire_peektype(msg), msg);

	return NULL;
}

bool send_next(struct inprog_state *state,
	       struct inprog_tx_state *tx_state,
	       struct wally_psbt **psbt)
{
	u8 *msg;
	bool finished = false;
	struct wally_psbt *updated_psbt;
	struct psbt_changeset *cs = tx_state->changeset;

	/* First we check our cached changes */
	msg = psbt_changeset_get_next(tmpctx, &state->channel_id, cs);
	if (msg)
		goto sendmsg;

	/* If we don't have any changes cached, go ask Alice for
	 * what changes they've got for us */
	updated_psbt = fetch_psbt_changes(state, tx_state, *psbt);

	/* We should always get a updated psbt back */
	if (!updated_psbt)
		;//DD open_err_fatal(state, "%s", "Uncaught error");

	tx_state->changeset = tal_free(tx_state->changeset);
	tx_state->changeset = psbt_get_changeset(tx_state, *psbt, updated_psbt);

	/* We want this old psbt to be cleaned up when the changeset is freed */
	tal_steal(tx_state->changeset, *psbt);
	*psbt = tal_steal(tx_state, updated_psbt);
	msg = psbt_changeset_get_next(tmpctx, &state->channel_id,
				      tx_state->changeset);
	/*
	 * If there's no more moves, we send tx_complete
	 * and reply that we're finished */
	if (!msg) {
		msg = towire_tx_complete(tmpctx, &state->channel_id);
		finished = true;
	}

sendmsg:
	sync_crypto_write(state->pps, msg);

	return !finished;
}

void add_funding_output(struct inprog_tx_state *tx_state,
			       struct inprog_state *state,
			       struct amount_sat total)
{
	const u8 *wscript;
	struct wally_psbt_output *funding_out;

	wscript = bitcoin_redeem_2of2(tmpctx, &state->our_funding_pubkey,
				      &state->their_funding_pubkey);
	funding_out = psbt_append_output(tx_state->psbt,
					 scriptpubkey_p2wsh(tmpctx, wscript),
					 total);

	/* Add a serial_id for this output */
	tx_state->funding_serial = psbt_new_input_serial(tx_state->psbt,
							 TX_INITIATOR);
	psbt_output_set_serial_id(tx_state->psbt,
				  funding_out,
				  tx_state->funding_serial);
}

bool run_tx_interactive(struct inprog_state *state,
			struct inprog_tx_state *tx_state,
			struct wally_psbt **orig_psbt,
			enum tx_role our_role)
{
	/* Opener always sends the first utxo info */
	bool we_complete = false, they_complete = false;
	u8 *msg;
	struct wally_psbt *psbt = *orig_psbt;

	while (!(we_complete && they_complete)) {
		struct channel_id cid;
		enum peer_wire t;
		u64 serial_id;

		/* Reset their_complete to false every round,
		 * they have to re-affirm every time  */
		they_complete = false;

		msg = NULL;//DD opening_negotiate_msg(tmpctx, state);
		if (!msg)
			return false;
		t = fromwire_peektype(msg);
		switch (t) {
		case WIRE_TX_ADD_INPUT: {
			const u8 *tx_bytes, *redeemscript;
			u32 sequence;
			size_t len;
			struct bitcoin_tx *tx;
			struct bitcoin_outpoint outpoint;
			struct amount_sat amt;

			if (!fromwire_tx_add_input(tmpctx, msg, &cid,
						   &serial_id,
						   cast_const2(u8 **,
							       &tx_bytes),
						   &outpoint.n, &sequence,
						   cast_const2(u8 **,
							       &redeemscript)))
				;//DD open_err_fatal(state,
				//DD	       "Parsing tx_add_input %s",
				//DD	       tal_hex(tmpctx, msg));

			//DD check_channel_id(state, &cid, &state->channel_id);

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 *   - MUST fail the negotiation if: ...
			 *   - if has received 4096 `tx_add_input`
			 *   messages during this negotiation
			 */
			//DD if (++tx_state->tx_msg_count[TX_ADD_INPUT] > MAX_TX_MSG_RCVD)
			//DD	open_err_warn(state, "Too many `tx_add_input`s"
			//DD		      " received %d", MAX_TX_MSG_RCVD);
			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 *   - MUST fail the negotiation if: ...
			 *   - the `serial_id` has the wrong parity
			 */
			if (serial_id % 2 == our_role)
				;//DD open_err_warn(state,
				//DD	      "Invalid serial_id rcvd. %"PRIu64,
				//DD	      serial_id);
			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 *   - MUST fail the negotiation if: ...
			 *   - the `serial_id` is already included in
			 *   the transaction
			 */
			if (psbt_find_serial_input(psbt, serial_id) != -1)
				;//DDopen_err_warn(state, "Duplicate serial_id rcvd."
				//DD	      " %"PRIu64, serial_id);

			/* Convert tx_bytes to a tx! */
			len = tal_bytelen(tx_bytes);
			tx = pull_bitcoin_tx(state, &tx_bytes, &len);
			if (!tx || len != 0)
				;//DD open_err_warn(state, "%s", "Invalid tx sent.");

			if (outpoint.n >= tx->wtx->num_outputs)
				;//DD open_err_warn(state,
				//DD	      "Invalid tx outnum sent. %u",
				//DD	      outpoint.n);
			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 *   - MUST fail the negotiation if: ...
			 *   - the `prevtx_out` input of `prevtx` is
			 *   not an `OP_0` to `OP_16` followed by a single push
			 */
			if (!is_segwit_output(&tx->wtx->outputs[outpoint.n],
					      redeemscript))
				;//DD open_err_warn(state,
				//DD	      "Invalid tx sent. Not SegWit %s",
				//DD	      type_to_string(tmpctx,
				//DD			     struct bitcoin_tx,
				//DD			     tx));

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 *   The receiving node: ...
			 *    - MUST fail the negotiation if:
			 *    - the `prevtx` and `prevtx_vout` are
			 *    identical to a previously added (and not
			 *    removed) input's
			 */
			bitcoin_txid(tx, &outpoint.txid);
			if (psbt_has_input(psbt, &outpoint))
				;//DD open_err_warn(state,
				//DD	      "Unable to add input %s- "
				//DD	      "already present",
				//DD	      type_to_string(tmpctx,
				//DD			     struct bitcoin_outpoint,
				//DD			     &outpoint));

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node:
			 *  - MUST add all received inputs to the transaction
			 */
			struct wally_psbt_input *in =
				psbt_append_input(psbt, &outpoint,
						  sequence, NULL,
						  NULL,
						  redeemscript);
			if (!in)
				;//DD open_err_warn(state,
				//DD	      "Unable to add input %s",
				//DD	      type_to_string(tmpctx,
				//DD			     struct bitcoin_outpoint,
				//DD			     &outpoint));

			tal_wally_start();
			wally_psbt_input_set_utxo(in, tx->wtx);
			tal_wally_end(psbt);

			if (is_elements(chainparams)) {
				struct amount_asset asset;

				bitcoin_tx_output_get_amount_sat(tx, outpoint.n,
								 &amt);

				/* FIXME: persist asset tags */
				asset = amount_sat_to_asset(&amt,
						chainparams->fee_asset_tag);
				/* FIXME: persist nonces */
				psbt_elements_input_set_asset(psbt,
							      outpoint.n,
							      &asset);
			}

			psbt_input_set_serial_id(psbt, in, serial_id);

			break;
		}
		case WIRE_TX_REMOVE_INPUT: {
			int input_index;

			if (!fromwire_tx_remove_input(msg, &cid, &serial_id))
				;//DD open_err_fatal(state,
				//DD	       "Parsing tx_remove_input %s",
				//DD	       tal_hex(tmpctx, msg));

			//DD check_channel_id(state, &cid, &state->channel_id);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node:  ...
			 *   - MUST fail the negotiation if: ...
			 *   - the input or output identified by the
			 *   `serial_id` was not added by the sender
			 */
			if (serial_id % 2 == our_role)
				;//DD open_err_warn(state,
				//DD	      "Invalid serial_id rcvd. %"PRIu64,
				//DD	      serial_id);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node:  ...
			 *   - MUST fail the negotiation if: ...
			 *   - the `serial_id` does not correspond
			 *     to a currently added input (or output)
			 */
			input_index = psbt_find_serial_input(psbt, serial_id);
			/* We choose to error/fail negotiation */
			if (input_index == -1)
				;//DD open_err_warn(state,
				//DD	      "No input added with serial_id"
				//DD	      " %"PRIu64, serial_id);

			psbt_rm_input(psbt, input_index);
			break;
		}
		case WIRE_TX_ADD_OUTPUT: {
			u64 value;
			u8 *scriptpubkey;
			struct wally_psbt_output *out;
			struct amount_sat amt;
			if (!fromwire_tx_add_output(tmpctx, msg, &cid,
						    &serial_id, &value,
						    &scriptpubkey))
				;//DD open_err_fatal(state,
				//DD	       "Parsing tx_add_output %s",
				//DD	       tal_hex(tmpctx, msg));
			//DD check_channel_id(state, &cid, &state->channel_id);

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - it has received 4096 `tx_add_output`
			 *   messages during this negotiation
			 */
			if (++tx_state->tx_msg_count[TX_ADD_OUTPUT] > MAX_TX_MSG_RCVD)
				;//DD open_err_warn(state,
				//DD	      "Too many `tx_add_output`s"
				//DD	      " received (%d)",
				//DD	      MAX_TX_MSG_RCVD);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - the `serial_id` has the wrong parity
			 */
			if (serial_id % 2 == our_role)
				;//DD open_err_warn(state,
				//DD	      "Invalid serial_id rcvd. %"PRIu64,
				//DD	      serial_id);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - the `serial_id` is already included
			 *   in the transaction */
			if (psbt_find_serial_output(psbt, serial_id) != -1)
				;//DD open_err_warn(state,
				//DD	      "Duplicate serial_id rcvd."
				//DD	      " %"PRIu64, serial_id);
			amt = amount_sat(value);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MAY fail the negotiation if `script`
			 *   is non-standard */
			if (!is_known_scripttype(scriptpubkey))
				;//DD open_err_warn(state, "Script is not standard");

			out = psbt_append_output(psbt, scriptpubkey, amt);
			psbt_output_set_serial_id(psbt, out, serial_id);
			break;
		}
		case WIRE_TX_REMOVE_OUTPUT: {
			int output_index;

			if (!fromwire_tx_remove_output(msg, &cid, &serial_id))
				;//DD open_err_fatal(state,
				//DD	       "Parsing tx_remove_output %s",
				//DD	       tal_hex(tmpctx, msg));

			//DD check_channel_id(state, &cid, &state->channel_id);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - the input or output identified by the
			 *   `serial_id` was not added by the sender
			 */
			if (serial_id % 2 == our_role)
				;//DD open_err_warn(state,
				//DD	      "Invalid serial_id rcvd."
				//DD	      " %"PRIu64, serial_id);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - the `serial_id` does not correspond to a
			 *     currently added input (or output)
			 */
			output_index = psbt_find_serial_output(psbt, serial_id);
			if (output_index == -1)
				;//DD open_err_warn(state, false,
				//DD	   "No output added with serial_id"
				//DD	   " %"PRIu64, serial_id);
			psbt_rm_output(psbt, output_index);
			break;
		}
		case WIRE_TX_COMPLETE:
			if (!fromwire_tx_complete(msg, &cid))
				;//DD open_err_fatal(state,
				//DD	       "Parsing tx_complete %s",
				//DD	       tal_hex(tmpctx, msg));
			//DD check_channel_id(state, &cid, &state->channel_id);
			they_complete = true;
			break;
		case WIRE_INIT:
		case WIRE_ERROR:
		case WIRE_WARNING:
		case WIRE_OPEN_CHANNEL:
		case WIRE_ACCEPT_CHANNEL:
		case WIRE_FUNDING_CREATED:
		case WIRE_FUNDING_SIGNED:
		case WIRE_FUNDING_LOCKED:
		case WIRE_SHUTDOWN:
		case WIRE_CLOSING_SIGNED:
		case WIRE_UPDATE_ADD_HTLC:
		case WIRE_UPDATE_FULFILL_HTLC:
		case WIRE_UPDATE_FAIL_HTLC:
		case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
		case WIRE_COMMITMENT_SIGNED:
		case WIRE_REVOKE_AND_ACK:
		case WIRE_UPDATE_FEE:
		case WIRE_UPDATE_BLOCKHEIGHT:
		case WIRE_CHANNEL_REESTABLISH:
		case WIRE_ANNOUNCEMENT_SIGNATURES:
		case WIRE_GOSSIP_TIMESTAMP_FILTER:
		case WIRE_OBS2_ONION_MESSAGE:
		case WIRE_ONION_MESSAGE:
		case WIRE_TX_SIGNATURES:
		case WIRE_OPEN_CHANNEL2:
		case WIRE_ACCEPT_CHANNEL2:
		case WIRE_INIT_RBF:
		case WIRE_ACK_RBF:
		case WIRE_CHANNEL_ANNOUNCEMENT:
		case WIRE_CHANNEL_UPDATE:
		case WIRE_NODE_ANNOUNCEMENT:
		case WIRE_QUERY_CHANNEL_RANGE:
		case WIRE_REPLY_CHANNEL_RANGE:
		case WIRE_QUERY_SHORT_CHANNEL_IDS:
		case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
		case WIRE_PING:
		case WIRE_PONG:
#if EXPERIMENTAL_FEATURES
		case WIRE_STFU:
#endif
			;//DD open_err_warn(state, "Unexpected wire message %s",
			//DD	      tal_hex(tmpctx, msg));
			return false;
		}

		if (!(we_complete && they_complete))
			we_complete = !send_next(state, tx_state, &psbt);
	}

	/* Sort psbt! */
	psbt_sort_by_serial_id(psbt);

	/* Return the 'finished' psbt */
	*orig_psbt = psbt;
	return true;
}
