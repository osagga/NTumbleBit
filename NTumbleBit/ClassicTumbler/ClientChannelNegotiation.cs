﻿using NBitcoin;
using NBitcoin.Crypto;
using NTumbleBit.PuzzlePromise;
using NTumbleBit.PuzzleSolver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NTumbleBit.ClassicTumbler
{
	public enum TumblerClientSessionStates
	{
		WaitingVoucher,
		WaitingTumblerClientTransactionKey,
		WaitingClientTransaction,
		WaitingSolvedVoucher,
		WaitingGenerateTumblerTransactionKey,
		WaitingTumblerEscrow,
		PromisePhase,
	}
	public class ClientChannelNegotiation
	{
		public class State
		{
			public State()
			{
			}

			public TumblerClientSessionStates Status
			{
				get; set;
			}

			public int CycleStart
			{
				get; set;
			}

			public byte[] SignedVoucher
			{
				get; set;
			}
			public UnsignedVoucherInformation UnsignedVoucher
			{
				get; set;
			}
			public PuzzleValue BlindedVoucher
			{
				get; set;
			}
			public BlindFactor BlindedVoucherFactor
			{
				get; set;
			}

			public Script TumblerEscrow
			{
				get; set;
			}
			public Script ClientEscrow
			{
				get; set;
			}
			public Key TumblerEscrowKey
			{
				get;
				set;
			}
			public Key ClientEscrowKey
			{
				get;
				set;
			}			
			public int TumblerEscrowKeyReference
			{
				get;
				set;
			}
			public uint160 ChannelId
			{
				get;
				set;
			}
		}
		public ClientChannelNegotiation(ClassicTumblerParameters parameters, int cycleStart)
		{
            InternalState = new State();
			Parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
			InternalState.CycleStart = cycleStart;
		}

		public ClientChannelNegotiation(ClassicTumblerParameters parameters, State state)
		{
            if (state == null)
				throw new ArgumentNullException(nameof(state));
			Parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
			InternalState = Serializer.Clone(state);
		}

		private State InternalState
		{
			get; set;
		}


		public TumblerClientSessionStates Status
		{
			get
			{
				return InternalState.Status;
			}
		}

		public State GetInternalState()
		{
			var clone = Serializer.Clone(InternalState);
			return clone;
		}


		public ClassicTumblerParameters Parameters
		{
			get;
			private set;
		}


		public void ReceiveUnsignedVoucher(UnsignedVoucherInformation voucher)
		{
			AssertState(TumblerClientSessionStates.WaitingVoucher);
			var puzzle = new Puzzle(Parameters.VoucherKey.PublicKey, voucher.Puzzle);
			InternalState.UnsignedVoucher = voucher;
			BlindFactor factor = null;
			InternalState.BlindedVoucher = puzzle.Blind(ref factor).PuzzleValue;
			InternalState.BlindedVoucherFactor = factor;
			InternalState.Status = TumblerClientSessionStates.WaitingTumblerClientTransactionKey;
		}
		
		/// <summary>
		/// Receiving the Tumbler escrow key of Client Escrow.
		/// </summary>
		/// <param name="tumblerKey"></param>
		/// <param name="keyReference"></param>
		public void ReceiveTumblerEscrowKey(PubKey tumblerKey, int keyReference)
		{
			AssertState(TumblerClientSessionStates.WaitingTumblerClientTransactionKey);
			var escrow = new Key();

			InternalState.ClientEscrow = new EscrowScriptPubKeyParameters()
			{
				Initiator = escrow.PubKey,
				Receiver = tumblerKey,
				LockTime = GetCycle().GetClientLockTime()
			}.ToScript();
			InternalState.ClientEscrowKey = escrow;
			InternalState.TumblerEscrowKeyReference = keyReference;
			InternalState.Status = TumblerClientSessionStates.WaitingClientTransaction;
		}

		public TxOut BuildClientEscrowTxOut()
		{
			// TODO: This function builds T_escr from Alice to the Tumbler
			AssertState(TumblerClientSessionStates.WaitingClientTransaction);
			// TODO: Change the first parameter HERE, I think we should make it as 'some multiple * Parameters.Denomination'!
			return new TxOut(Parameters.Denomination + Parameters.Fee, InternalState.ClientEscrow.WitHash.ScriptPubKey.Hash);
		}
		
		public SolverClientSession SetClientSignedTransaction(uint160 channelId, Transaction transaction, Script redeemDestination)
		{
			AssertState(TumblerClientSessionStates.WaitingClientTransaction);
			var expectedTxout = BuildClientEscrowTxOut();
			var output = transaction.Outputs.AsIndexedOutputs().Single(o => o.TxOut.ScriptPubKey == expectedTxout.ScriptPubKey && o.TxOut.Value == expectedTxout.Value);
			var solver = new SolverClientSession(Parameters.CreateSolverParamaters());
			solver.ConfigureEscrowedCoin(channelId, new Coin(output).ToScriptCoin(InternalState.ClientEscrow), InternalState.ClientEscrowKey, redeemDestination);
			InternalState.Status = TumblerClientSessionStates.WaitingSolvedVoucher;
			return solver;
		}

		public void CheckVoucherSolution(PuzzleSolution blindedVoucherSignature)
		{
			AssertState(TumblerClientSessionStates.WaitingSolvedVoucher);
			var solution = blindedVoucherSignature.Unblind(Parameters.VoucherKey.PublicKey, InternalState.BlindedVoucherFactor);
			if(!InternalState.UnsignedVoucher.Puzzle.WithRsaKey(Parameters.VoucherKey.PublicKey).Verify(solution))
				throw new PuzzleException("Incorrect puzzle solution");
			InternalState.BlindedVoucherFactor = null;
			InternalState.SignedVoucher = new XORKey(solution).XOR(InternalState.UnsignedVoucher.EncryptedSignature);
			InternalState.UnsignedVoucher.EncryptedSignature = new byte[0];
			InternalState.ClientEscrowKey = null;
			InternalState.Status = TumblerClientSessionStates.WaitingGenerateTumblerTransactionKey;
		}

		public OpenChannelRequest GetOpenChannelRequest(int bobPaymentCount)
		{
			AssertState(TumblerClientSessionStates.WaitingGenerateTumblerTransactionKey);
			var escrow = new Key();
			InternalState.TumblerEscrowKey = escrow;
			InternalState.Status = TumblerClientSessionStates.WaitingTumblerEscrow;
			/*
			TODO:
				- Here we need to send to the Tumbler how much 'Q' we are requesting as part of the request.
					-  We can call the field "RequestedPaymentsCount" (in the 'OpenChannelRequest' class), and we can get this value by:
						- Either passed to this function as a parameter.
			Cleaner ->	- Or it could be saved in the InternalState by default and just referenced here when creating the Request.
			*/
					
			var result = new OpenChannelRequest
			{
				EscrowKey = escrow.PubKey,
				Signature = InternalState.SignedVoucher,
				CycleStart = InternalState.UnsignedVoucher.CycleStart,
				RequestedPaymentsCount = bobPaymentCount,
				Nonce = InternalState.UnsignedVoucher.Nonce,
			};
			InternalState.SignedVoucher = null;
			InternalState.UnsignedVoucher = null;
			return result;
		}

		public PromiseClientSession ReceiveTumblerEscrowedCoin(ScriptCoin escrowedCoin, Script TumblerChangeAddress)
		{
			// TODO: This function should also expect another input that is "change_adress" of the Tumbler
			// the second input should be saved in the "InternalState" along with the Escrow.
			AssertState(TumblerClientSessionStates.WaitingTumblerEscrow);
			var escrow = EscrowScriptPubKeyParameters.GetFromCoin(escrowedCoin);
			if(escrow == null)
				throw new PuzzleException("invalid-escrow");
			if(!escrowedCoin.IsP2SH || escrowedCoin.RedeemType != RedeemType.WitnessV0)
				throw new PuzzleException("invalid-escrow");
			var expectedEscrow = GetTumblerEscrowParameters(escrow.Initiator);
			if(escrow != expectedEscrow)
				throw new PuzzleException("invalid-escrow");

			// TODO: Here we need to change "Parameters.Denomination" to "Parameters.Denomination * Parameters.BobPaymentsCount"
			if(escrowedCoin.Amount != Parameters.Denomination)
				throw new PuzzleException("invalid-amount");


			InternalState.Status = TumblerClientSessionStates.PromisePhase;
			var session = new PromiseClientSession(Parameters.CreatePromiseParamaters());
			session.SetChannelId(InternalState.ChannelId);
			session.ConfigureEscrowedCoin(escrowedCoin, InternalState.TumblerEscrowKey);
			session.ConfigureTumblerCashOutAddress(TumblerChangeAddress);
			InternalState.TumblerEscrowKey = null;
			return session;
		}

		public EscrowScriptPubKeyParameters GetTumblerEscrowParameters(PubKey pubkey)
		{
			return new EscrowScriptPubKeyParameters()
			{
				Initiator = pubkey,
				Receiver = InternalState.TumblerEscrowKey.PubKey,
				LockTime = GetCycle().GetTumblerLockTime()
			};
		}

		internal void SetChannelId(uint160 channelId)
		{
            InternalState.ChannelId = channelId ?? throw new ArgumentNullException(nameof(channelId));
		}

		public CycleParameters GetCycle()
		{
			return Parameters.CycleGenerator.GetCycle(InternalState.CycleStart);
		}

		private void AssertState(TumblerClientSessionStates state)
		{
			if(state != InternalState.Status)
				throw new InvalidStateException("Invalid state, actual " + InternalState.Status + " while expected is " + state);
		}
	}
}
