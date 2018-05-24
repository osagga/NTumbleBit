﻿using NBitcoin;
using NTumbleBit.PuzzleSolver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NTumbleBit.ClassicTumbler;
using NBitcoin.BuilderExtensions;

namespace NTumbleBit
{
	public interface IEscrow
	{
		ScriptCoin EscrowedCoin
		{
			get;
		}
	}
	public abstract class EscrowInitiator : IEscrow
	{
		public class State
		{
			public ScriptCoin EscrowedCoin
			{
				get;
				set;
			}
			public Key EscrowKey
			{
				get;
				set;
			}

            /// <summary>
			/// Amount by which the transaction fee will be amplified.
			/// </summary>
            public int FeeFactor
            {
                get;
                set;
            } = 5;

            public Script RedeemDestination
			{
				get;
				set;
			}

			public Script TumblerCashOutDestination
			{
				get;
				set;
			}
			

			/// <summary>
			/// Identify the channel to the tumbler
			/// </summary>
			public uint160 ChannelId
			{
				get;
				set;
			}
		}

		protected State InternalState
		{
			get; set;
		}

		public virtual void ConfigureEscrowedCoin(uint160 channelId, ScriptCoin escrowedCoin, Key escrowKey, Script redeemDestination)
		{
			if(escrowedCoin == null)
				throw new ArgumentNullException(nameof(escrowedCoin));
			if(escrowKey == null)
				throw new ArgumentNullException(nameof(escrowKey));
            var escrow = EscrowScriptPubKeyParameters.GetFromCoin(escrowedCoin);
			if(escrow == null ||
				escrow.Initiator != escrowKey.PubKey)
				throw new PuzzleException("Invalid escrow");
            InternalState.ChannelId = channelId ?? throw new ArgumentNullException(nameof(channelId));
			InternalState.EscrowedCoin = escrowedCoin;
			InternalState.EscrowKey = escrowKey;
			InternalState.RedeemDestination = redeemDestination ?? throw new ArgumentNullException(nameof(redeemDestination));
		}

		public virtual void ConfigureTumblerCashOutAddress(Script tumblerCashoutAddress)
		{
            InternalState.TumblerCashOutDestination = tumblerCashoutAddress ?? throw new ArgumentNullException(nameof(tumblerCashoutAddress));
		}

		public TrustedBroadcastRequest CreateRedeemTransaction(FeeRate feeRate)
		{
			if(feeRate == null)
				throw new ArgumentNullException(nameof(feeRate));

			var escrow = EscrowScriptPubKeyParameters.GetFromCoin(InternalState.EscrowedCoin);
			var escrowCoin = InternalState.EscrowedCoin;
			Transaction tx = new Transaction();
			tx.LockTime = escrow.LockTime;
			tx.Inputs.Add(new TxIn());
			//Put a dummy signature and the redeem script
			tx.Inputs[0].ScriptSig =
				new Script(
					Op.GetPushOp(TrustedBroadcastRequest.PlaceholderSignature),
					Op.GetPushOp(escrowCoin.Redeem.ToBytes()));
			tx.Inputs[0].Witnessify();
			tx.Inputs[0].Sequence = 0;
			// NOTE: I don't think we need to play with the 'Amount' here since it really just
			// depends on what the escrowCoin had initially, so this value will follow whatever
			// we initially set the escrow to have.
			tx.Outputs.Add(new TxOut(escrowCoin.Amount, InternalState.RedeemDestination));
            
            // We modify the fee here by the expected factor.
			tx.Outputs[0].Value -= (feeRate.GetFee(tx.GetVirtualSize()) * InternalState.FeeFactor);

			var redeemTransaction = new TrustedBroadcastRequest
			{
				Key = InternalState.EscrowKey,
				PreviousScriptPubKey = escrowCoin.ScriptPubKey,
				Transaction = tx,
				KnownPrevious = new Coin[] { escrowCoin }
			};
			return redeemTransaction;
		}

		public abstract LockTime GetLockTime(CycleParameters cycle);

		public uint160 Id
		{
			get
			{
				return InternalState.ChannelId;
			}
		}

		public ScriptCoin EscrowedCoin
		{
			get
			{
				return InternalState.EscrowedCoin;
			}
		}
	}
}
