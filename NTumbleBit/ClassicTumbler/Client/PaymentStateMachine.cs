using Microsoft.Extensions.Logging;
using NBitcoin;
using NTumbleBit.ClassicTumbler.Server.Models;
using NTumbleBit.Logging;
using NTumbleBit.PuzzlePromise;
using NTumbleBit.PuzzleSolver;
using NTumbleBit.Services;
using System;
using System.Linq;

namespace NTumbleBit.ClassicTumbler.Client
{
    public enum PaymentStateMachineStatus
	{
		New,
		Registered,
		ClientChannelBroadcasted,
		TumblerVoucherSigning,
		TumblerVoucherObtained,

		//TODO Remove later, keep so it does not crash testers
		TumblerChannelBroadcasted,
		TumblerChannelConfirmed,
		//

		PuzzleSolutionObtained,
		UncooperativeTumbler,
		TumblerChannelCreating,
		TumblerChannelCreated,
		TumblerChannelSecured,
		ProcessingPayment,
		Wasted,
	}
	public class PaymentStateMachine
	{
		public TumblerClientRuntime Runtime
		{
			get; set;
		}
		public PaymentStateMachine(
			TumblerClientRuntime runtime)
		{
            Runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
		}




		public PaymentStateMachine(
			TumblerClientRuntime runtime,
			State state) : this(runtime)
		{
			if(state == null)
				return;

			runtime.TumblerParameters.AlicePaymentsCount = 3;
			runtime.TumblerParameters.BobPaymentsCount = 3;

			if(state.NegotiationClientState != null)
			{
				StartCycle = state.NegotiationClientState.CycleStart;
				ClientChannelNegotiation = new ClientChannelNegotiation(runtime.TumblerParameters, state.NegotiationClientState);
			}
			if(state.PromiseClientState != null){
				PromiseClientSession = new PromiseClientSession(runtime.TumblerParameters.CreatePromiseParamaters(), state.PromiseClientState);
			}	
			if(state.SolverClientState != null){
				SolverClientSession = new SolverClientSession(runtime.TumblerParameters.CreateSolverParamaters(), state.SolverClientState);
			}
				
				
			Status = state.Status;
		}

		public Tracker Tracker
		{
			get
			{
				return Runtime.Tracker;
			}
		}
		public ExternalServices Services
		{
			get
			{
				return Runtime.Services;
			}
		}

		public ClassicTumblerParameters Parameters
		{
			get
			{
				return Runtime.TumblerParameters;
			}
		}
		public int StartCycle
		{
			get; set;
		}
		public ClientChannelNegotiation ClientChannelNegotiation
		{
			get; set;
		}

		public SolverClientSession SolverClientSession
		{
			get; set;
		}
		public PromiseClientSession PromiseClientSession
		{
			get;
			private set;
		}
		public IDestinationWallet DestinationWallet
		{
			get
			{
				return Runtime.DestinationWallet;
			}
		}
		public bool Cooperative
		{
			get
			{
				return Runtime.Cooperative;
			}
		}

		public class State
		{
			public uint160 TumblerParametersHash
			{
				get; set;
			}
			public ClientChannelNegotiation.State NegotiationClientState
			{
				get;
				set;
			}
			public PromiseClientSession.State PromiseClientState
			{
				get;
				set;
			}
			public SolverClientSession.State SolverClientState
			{
				get;
				set;
			}
			public PaymentStateMachineStatus Status
			{
				get;
				set;
			}
		}

		public State GetInternalState()
		{
			State s = new State();
			if(SolverClientSession != null)
				s.SolverClientState = SolverClientSession.GetInternalState();
			if(PromiseClientSession != null)
				s.PromiseClientState = PromiseClientSession.GetInternalState();
			if(ClientChannelNegotiation != null)
				s.NegotiationClientState = ClientChannelNegotiation.GetInternalState();
			s.Status = Status;
			s.TumblerParametersHash = Parameters.GetHash();
			return s;
		}

		public PaymentStateMachineStatus Status
		{
			get;
			set;
		}

		public bool NeedSave
		{
			get; set;
		}

		public void Update()
		{
			int height = Services.BlockExplorerService.GetCurrentHeight();
			CycleParameters cycle;
			CyclePhase phase;
			if(ClientChannelNegotiation == null)
			{
				cycle = Parameters.CycleGenerator.GetRegisteringCycle(height);
				phase = CyclePhase.Registration;
			}
			else
			{
				cycle = ClientChannelNegotiation.GetCycle();
				var phases = new CyclePhase[]
				{
					CyclePhase.Registration,
					CyclePhase.ClientChannelEstablishment,
					CyclePhase.TumblerChannelEstablishment,
					CyclePhase.PaymentPhase,
					CyclePhase.TumblerCashoutPhase,
					CyclePhase.ClientCashoutPhase
				};
				if(!phases.Any(p => cycle.IsInPhase(p, height)))
					return;
				phase = phases.First(p => cycle.IsInPhase(p, height));
			}


			Logs.Client.LogInformation(Environment.NewLine);
			var period = cycle.GetPeriods().GetPeriod(phase);
			var blocksLeft = period.End - height;
			Logs.Client.LogInformation($"Cycle {cycle.Start} ({Status})");
			Logs.Client.LogInformation($"{cycle.ToString(height)} in phase {phase} ({blocksLeft} more blocks)");
			var previousState = Status;

			TumblerClient bob = null, alice = null;
			// NOTE: We can either be Bob or Alice here, so this works for both.
			try
			{

				var correlation = SolverClientSession == null ? CorrelationId.Zero : new CorrelationId(SolverClientSession.Id);

				FeeRate feeRate = null;
				switch(phase)
				{
					case CyclePhase.Registration:
						if(Status == PaymentStateMachineStatus.New)
						{
							bob = Runtime.CreateTumblerClient(cycle.Start, Identity.Bob);
							//Client asks for voucher
							var voucherResponse = bob.AskUnsignedVoucher();
							NeedSave = true;
							//Client ensures he is in the same cycle as the tumbler (would fail if one tumbler or client's chain isn't sync)
							var tumblerCycle = Parameters.CycleGenerator.GetCycle(voucherResponse.CycleStart);
							Assert(tumblerCycle.Start == cycle.Start, "invalid-phase");
							//Saving the voucher for later
							StartCycle = cycle.Start;
							ClientChannelNegotiation = new ClientChannelNegotiation(Parameters, cycle.Start);
							// Note: This saves the Voucher so that Alice can access it.
							ClientChannelNegotiation.ReceiveUnsignedVoucher(voucherResponse);
							Status = PaymentStateMachineStatus.Registered;
						}
						break;
					case CyclePhase.ClientChannelEstablishment:
						if(Status == PaymentStateMachineStatus.Registered)
						{
							alice = Runtime.CreateTumblerClient(cycle.Start, Identity.Alice);
							var key = alice.RequestTumblerEscrowKey();
							ClientChannelNegotiation.ReceiveTumblerEscrowKey(key.PubKey, key.KeyIndex);
							
							/*
								TODO [DONE]: The amount of money Alice escrows here depends on the 'Parameters' that were
								passed to the ClientChannelNegotiation.
							 */

							//Client create the escrow
							var escrowTxOut = ClientChannelNegotiation.BuildClientEscrowTxOut();
							feeRate = GetFeeRate();

							// NOTE: This part just checks if Alice has enough funding to support the transaction 'escrowTxOut'
							Transaction clientEscrowTx = null;
							try
							{
								clientEscrowTx = Services.WalletService.FundTransactionAsync(escrowTxOut, feeRate).GetAwaiter().GetResult();
							}
							catch(NotEnoughFundsException ex)
							{
								Logs.Client.LogInformation($"Not enough funds in the wallet to tumble. Missing about {ex.Missing}. Denomination is {Parameters.Denomination}.");
								break;
							}
							NeedSave = true;
							// 
							var redeemDestination = Services.WalletService.GenerateAddressAsync().GetAwaiter().GetResult().ScriptPubKey;
							var channelId = new uint160(RandomUtils.GetBytes(20));
							
							// NOTE: It seems like this function checks the Escrow, stores the Escrow Tx along with the address to receive the refund at.
							SolverClientSession = ClientChannelNegotiation.SetClientSignedTransaction(channelId, clientEscrowTx, redeemDestination);

							correlation = new CorrelationId(SolverClientSession.Id);

							Tracker.AddressCreated(cycle.Start, TransactionType.ClientEscrow, escrowTxOut.ScriptPubKey, correlation);
							Tracker.TransactionCreated(cycle.Start, TransactionType.ClientEscrow, clientEscrowTx.GetHash(), correlation);
							Services.BlockExplorerService.TrackAsync(escrowTxOut.ScriptPubKey).GetAwaiter().GetResult();

							// NOTE: This the same as T_refund from the the escrow, this doesn't need to be modified since Alice will take 
							// All the Q BTCs here, and not give any change to the Tumbler.
							var redeemTx = SolverClientSession.CreateRedeemTransaction(feeRate);
							Tracker.AddressCreated(cycle.Start, TransactionType.ClientRedeem, redeemDestination, correlation);

							//redeemTx does not be to be recorded to the tracker, this is TrustedBroadcastService job

							Services.BroadcastService.BroadcastAsync(clientEscrowTx).GetAwaiter().GetResult();

							Services.TrustedBroadcastService.Broadcast(cycle.Start, TransactionType.ClientRedeem, correlation, redeemTx);
							Status = PaymentStateMachineStatus.ClientChannelBroadcasted;
						}
						else if(Status == PaymentStateMachineStatus.ClientChannelBroadcasted)
						{
							alice = Runtime.CreateTumblerClient(cycle.Start, Identity.Alice);
							// NOTE: This function tracks the given Tx from the Blockchain, might need something like that
							// On the Tumbler side to get the amount of BTCs Alice has escrowed.
							TransactionInformation clientTx = GetTransactionInformation(SolverClientSession.EscrowedCoin, true);
							
							var state = ClientChannelNegotiation.GetInternalState();
							if(clientTx != null && clientTx.Confirmations >= cycle.SafetyPeriodDuration)
							{
								Logs.Client.LogInformation($"Client escrow reached {cycle.SafetyPeriodDuration} confirmations");
								//Client asks the public key of the Tumbler and sends its own
								alice.BeginSignVoucher(new SignVoucherRequest
								{
									MerkleProof = clientTx.MerkleProof,
									Transaction = clientTx.Transaction,
									KeyReference = state.TumblerEscrowKeyReference,
									UnsignedVoucher = state.BlindedVoucher,
									Cycle = cycle.Start,
									ClientEscrowKey = state.ClientEscrowKey.PubKey,
									ChannelId = SolverClientSession.Id
								});
								NeedSave = true;
								Status = PaymentStateMachineStatus.TumblerVoucherSigning;
							}
						}
						else if(Status == PaymentStateMachineStatus.TumblerVoucherSigning)
						{
							alice = Runtime.CreateTumblerClient(cycle.Start, Identity.Alice);
							var voucher = alice.EndSignVoucher(SolverClientSession.Id);
							if(voucher != null)
							{
								ClientChannelNegotiation.CheckVoucherSolution(voucher);
								NeedSave = true;
								Status = PaymentStateMachineStatus.TumblerVoucherObtained;
							}
						}
						break;
					case CyclePhase.TumblerChannelEstablishment:

						if(Status == PaymentStateMachineStatus.TumblerVoucherObtained)
						{
							// NOTE: After this stage, the Tumbler would have ecrowed the requested BTCs
							bob = Runtime.CreateTumblerClient(cycle.Start, Identity.Bob);
							Logs.Client.LogInformation("Begin ask to open the channel...");
							//Client asks the Tumbler to make a channel
							
							// TODO [DEBUG]: Make sure that the value passed here is actually what we set on top.
							var bobEscrowInformation = ClientChannelNegotiation.GetOpenChannelRequest(PromiseClientSession.Parameters.PaymentsCount);
							
							uint160 channelId = null;
							
							try
							{
								channelId = bob.BeginOpenChannel(bobEscrowInformation);
								NeedSave = true;
							}
							catch(Exception ex)
							{
								if(ex.Message.Contains("tumbler-insufficient-funds"))
								{
									Logs.Client.LogWarning("The tumbler server has not enough funds and can't open a channel for now");
									break;
								}
								throw;
							}
							ClientChannelNegotiation.SetChannelId(channelId);
							Status = PaymentStateMachineStatus.TumblerChannelCreating;

						}
						else if(Status == PaymentStateMachineStatus.TumblerChannelCreating)
						{
							bob = Runtime.CreateTumblerClient(cycle.Start, Identity.Bob);
							var tumblerEscrow = bob.EndOpenChannel(cycle.Start, ClientChannelNegotiation.GetInternalState().ChannelId);
							if(tumblerEscrow == null)
							{
								Logs.Client.LogInformation("Tumbler escrow still creating...");
								break;
							}
							NeedSave = true;

							if(tumblerEscrow.OutputIndex >= tumblerEscrow.Transaction.Outputs.Count)
							{
								Logs.Client.LogError("Tumbler escrow output out-of-bound");
								Status = PaymentStateMachineStatus.Wasted;
								break;
							}

							if(tumblerEscrow.ChangeAddress == null)
							{
								Logs.Client.LogError("Tumbler didn't send a cashOut wallet address");
								Status = PaymentStateMachineStatus.Wasted;
								break;
							}

							var txOut = tumblerEscrow.Transaction.Outputs[tumblerEscrow.OutputIndex];
							var outpoint = new OutPoint(tumblerEscrow.Transaction.GetHash(), tumblerEscrow.OutputIndex);
							var escrowCoin = new Coin(outpoint, txOut).ToScriptCoin(ClientChannelNegotiation.GetTumblerEscrowParameters(tumblerEscrow.EscrowInitiatorKey).ToScript());
							
							// NOTE: This saves the Tumbler cashoutAddress so that it can be recalled internally.
							PromiseClientSession = ClientChannelNegotiation.ReceiveTumblerEscrowedCoin(escrowCoin, tumblerEscrow.ChangeAddress);

							Logs.Client.LogInformation("Tumbler expected escrowed coin received");
							
							//Tell to the block explorer we need to track that address (for checking if it is confirmed in payment phase)
							Services.BlockExplorerService.TrackAsync(PromiseClientSession.EscrowedCoin.ScriptPubKey).GetAwaiter().GetResult();
							Services.BlockExplorerService.TrackPrunedTransactionAsync(tumblerEscrow.Transaction, tumblerEscrow.MerkleProof).GetAwaiter().GetResult();

							Tracker.AddressCreated(cycle.Start, TransactionType.TumblerEscrow, PromiseClientSession.EscrowedCoin.ScriptPubKey, correlation);
							Tracker.TransactionCreated(cycle.Start, TransactionType.TumblerEscrow, PromiseClientSession.EscrowedCoin.Outpoint.Hash, correlation);

							Services.BroadcastService.BroadcastAsync(tumblerEscrow.Transaction).GetAwaiter().GetResult();
							
							//Channel is done, now need to run the promise protocol to get valid puzzle
							var cashoutDestination = DestinationWallet.GetNewDestination();
							Tracker.AddressCreated(cycle.Start, TransactionType.TumblerCashout, cashoutDestination, correlation);

							feeRate = GetFeeRate();

							var sigReq = PromiseClientSession.CreateSignatureRequest(cashoutDestination, feeRate);
							var commitments = bob.SignHashes(PromiseClientSession.Id, sigReq);
							var revelation = PromiseClientSession.Reveal(commitments);
							var proof = bob.CheckRevelation(PromiseClientSession.Id, revelation);
							var puzzles = PromiseClientSession.CheckCommitmentProof(proof);
							/*
							TODO [DESIGN]: Need to figure out a way to coordinate the puzzles from Bob to Alice.
								- Should I just send all of them at once from Bob to Alice? Or One by one.
									- It might be a bit tricky doing the one by one approach given that this function is 
										run by threads and it's not continuos.
							 */
							 // TODO [DONE]: Define this Puzzles list that simulates Alice receiving all of the puzzles at once (since they are the same person for now)
                            SolverClientSession.Parameters.Puzzles = puzzles;
							
							// TODO [DONE]: This is the number of the puzzle we are currently solving.
                            SolverClientSession.Parameters.CurrentPuzzleNum = 1;
							
							Status = PaymentStateMachineStatus.TumblerChannelCreated;
						}
						else if(Status == PaymentStateMachineStatus.TumblerChannelCreated)
						{
							// TODO[DESIGN]: Need to figure out wether we keep this or change the part about counting bobs based on the outputvalue.
							CheckTumblerChannelSecured(cycle);
						}
						break;
					case CyclePhase.PaymentPhase:
						//Could have confirmed during safe period
						//Only check for the first block when period start, 
						//else Tumbler can know deanonymize you based on the timing of first Alice request if the transaction was not confirmed previously
						if(Status == PaymentStateMachineStatus.TumblerChannelCreated && height == period.Start)
						{
							// TODO: Need to figure out wether we keep this or change the part about counting bobs based on the outputvalue.
							CheckTumblerChannelSecured(cycle);
						}
						//No "else if" intended
						if(Status == PaymentStateMachineStatus.TumblerChannelSecured)
						{
							alice = Runtime.CreateTumblerClient(cycle.Start, Identity.Alice);
							Logs.Client.LogDebug("Starting the puzzle solver protocol...");

                            // NOTE: This function assumes that Parameters.CurrentPuzzleNum is the puzzle that we need to get the solution for.
                            SolverClientSession.AcceptPuzzle();

							var puzzles = SolverClientSession.GeneratePuzzles();
							alice.BeginSolvePuzzles(SolverClientSession.Id, puzzles);

							NeedSave = true;
							Status = PaymentStateMachineStatus.ProcessingPayment;
						}
						else if(Status == PaymentStateMachineStatus.ProcessingPayment)
						{
							feeRate = GetFeeRate();
							alice = Runtime.CreateTumblerClient(cycle.Start, Identity.Alice);
							var commitments = alice.EndSolvePuzzles(SolverClientSession.Id);
							NeedSave = true;
							if(commitments == null)
							{
								Logs.Client.LogDebug("Still solving puzzles...");
								break;
							}
							var revelation2 = SolverClientSession.Reveal(commitments);
							var solutionKeys = alice.CheckRevelation(SolverClientSession.Id, revelation2);
							var blindFactors = SolverClientSession.GetBlindFactors(solutionKeys);
							var offerInformation = alice.CheckBlindFactors(SolverClientSession.Id, blindFactors);
                            
							// NOTE: It seems like this creates and signs T_puzzle
							// TODO: Finish some work inside.
							var offerSignature = SolverClientSession.SignOffer(offerInformation);
							
							// NOTE: It seems like this function creates the redeem transaction for T_puzzle
							// TODO: finish some work inside.
							var offerRedeem = SolverClientSession.CreateOfferRedeemTransaction(feeRate);
							
							Logs.Client.LogDebug("Puzzle solver protocol ended...");

							//May need to find solution in the fulfillment transaction
							Services.BlockExplorerService.TrackAsync(offerRedeem.PreviousScriptPubKey).GetAwaiter().GetResult();
							Tracker.AddressCreated(cycle.Start, TransactionType.ClientOfferRedeem, SolverClientSession.GetInternalState().RedeemDestination, correlation);
							Services.TrustedBroadcastService.Broadcast(cycle.Start, TransactionType.ClientOfferRedeem, correlation, offerRedeem);
							
							try
							{
								solutionKeys = alice.FulfillOffer(SolverClientSession.Id, offerSignature);
								SolverClientSession.CheckSolutions(solutionKeys);
								var tumblingSolution = SolverClientSession.GetSolution();
								var transaction = PromiseClientSession.GetSignedTransaction(tumblingSolution, SolverClientSession.Parameters.CurrentPuzzleNum);
								Logs.Client.LogDebug("Got puzzle solution cooperatively from the tumbler");
								// TODO [DESIGN]: Only switch to 'PuzzleSolutionObtained' if we are done with the puzzles, otherwise, keep on the same state.
								Status = PaymentStateMachineStatus.PuzzleSolutionObtained;
                                //NOTE: Bob would cashout only in the cashOut phase, not in this phase.
								Services.TrustedBroadcastService.Broadcast(cycle.Start, TransactionType.TumblerCashout, correlation, new TrustedBroadcastRequest()
								{
									BroadcastAt = cycle.GetPeriods().ClientCashout.Start,
									Transaction = transaction
								});
								if(Cooperative)
								{
                                    // If Alice is Cooperative, we make T_cash and give it to the Tumbler
									try
									{
										// No need to await for it, it is a just nice for the tumbler (we don't want the underlying socks connection cut before the escape key is sent)
										var signature = SolverClientSession.SignEscape();
										alice.GiveEscapeKeyAsync(SolverClientSession.Id, signature).GetAwaiter().GetResult();
									}
									catch(Exception ex) { Logs.Client.LogDebug(new EventId(), ex, "Exception while giving the escape key"); }
									Logs.Client.LogInformation("Gave escape signature to the tumbler");
								}
							}
							catch(Exception ex)
							{
								Status = PaymentStateMachineStatus.UncooperativeTumbler;
								Logs.Client.LogWarning("The tumbler did not gave puzzle solution cooperatively");
								Logs.Client.LogWarning(ex.ToString());
							}
						}

						break;
					case CyclePhase.ClientCashoutPhase:

						//If the tumbler is uncooperative, he published solutions on the blockchain
						if(Status == PaymentStateMachineStatus.UncooperativeTumbler)
						{
							var transactions = Services.BlockExplorerService.GetTransactionsAsync(SolverClientSession.GetInternalState().OfferCoin.ScriptPubKey, false).GetAwaiter().GetResult();
							if(transactions.Count != 0)
							{
								SolverClientSession.CheckSolutions(transactions.Select(t => t.Transaction).ToArray());
								Logs.Client.LogInformation("Puzzle solution recovered from tumbler's fulfill transaction");
								NeedSave = true;
								Status = PaymentStateMachineStatus.PuzzleSolutionObtained;
								var tumblingSolution = SolverClientSession.GetSolution();
								var transaction = PromiseClientSession.GetSignedTransaction(tumblingSolution, 0);
								Tracker.TransactionCreated(cycle.Start, TransactionType.TumblerCashout, transaction.GetHash(), correlation);
								Services.BroadcastService.BroadcastAsync(transaction).GetAwaiter().GetResult();
							}
						}

						break;
				}
			}
			catch(InvalidStateException ex)
			{
				Logs.Client.LogDebug(new EventId(), ex, "Client side Invalid State, the payment is wasted");
				Status = PaymentStateMachineStatus.Wasted;
			}
			catch(Exception ex) when(ex.Message.IndexOf("invalid-state", StringComparison.OrdinalIgnoreCase) >= 0)
			{
				Logs.Client.LogDebug(new EventId(), ex, "Tumbler side Invalid State, the payment is wasted");
				Status = PaymentStateMachineStatus.Wasted;
			}
			finally
			{
				if(previousState != Status)
				{
					Logs.Client.LogInformation($"Status changed {previousState} => {Status}");
				}
				if(alice != null && bob != null)
					throw new InvalidOperationException("Bob and Alice have been both initialized, please report the bug to NTumbleBit developers");
				if(alice != null)
					alice.Dispose();
				if(bob != null)
					bob.Dispose();
			}
		}


		public bool ShouldStayConnected()
		{
			// TODO: Modify this to reflect the new conditions in the solver protocol
			if(ClientChannelNegotiation == null)
				return false;

			var cycle = ClientChannelNegotiation.GetCycle();

			if(
				// You get the solution of the puzzle
				Status == PaymentStateMachineStatus.PuzzleSolutionObtained &&
				// But have not yet cashed out
				!IsConfirmed(cycle, TransactionType.TumblerCashout))
			{
				return true;
			}

			if(
				// You do not have the solution
				Status == PaymentStateMachineStatus.UncooperativeTumbler &&
				// But have not yet redeemed or cashed out
				!(IsConfirmed(cycle, TransactionType.ClientRedeem) || IsConfirmed(cycle, TransactionType.ClientOfferRedeem) || IsConfirmed(cycle, TransactionType.TumblerCashout)))
			{
				return true;
			}
			return false;
		}

		private bool IsConfirmed(CycleParameters cycle, TransactionType transactionType)
		{
			foreach(var tx in Tracker.GetRecords(cycle.Start).Where(t => t.RecordType == RecordType.Transaction && t.TransactionType == transactionType))
			{
				var txInfo = Services.BlockExplorerService.GetTransaction(tx.TransactionId, true);
				if(txInfo != null && txInfo.Confirmations >= cycle.SafetyPeriodDuration)
				{
					return true;
				}
			}
			return false;
		}

		private void CheckTumblerChannelSecured(CycleParameters cycle)
		{
			TransactionInformation tumblerTx = GetTransactionInformation(PromiseClientSession.EscrowedCoin, false);
			if(tumblerTx == null)
			{
				Logs.Client.LogInformation($"Tumbler escrow not yet broadcasted");
				return;
			}

			if(tumblerTx.Confirmations >= cycle.SafetyPeriodDuration)
			{
				/*
					TODO (problem?): It seems that this function counts how many Bobs there are, but 
						it depends on the amount of the transaction to figure out how many transactions there are.
						The problem is that in this Mode, it's possible that each Bob escrows a diffrent amount of payments.
						So we can't use the transaction amount as a filter, maybe use something else? (PubKey?)
				 */
				var bobCount = Parameters.CountEscrows(tumblerTx.Transaction, Identity.Bob);
				Logs.Client.LogInformation($"Tumbler escrow reached {cycle.SafetyPeriodDuration} confirmations");
				Logs.Client.LogInformation($"Tumbler escrow transaction has {bobCount} users");
				Status = PaymentStateMachineStatus.TumblerChannelSecured;
				NeedSave = true;
				return;
			}

			if(tumblerTx.Confirmations < cycle.SafetyPeriodDuration)
			{
				Logs.Client.LogInformation($"Tumbler escrow need {cycle.SafetyPeriodDuration - tumblerTx.Confirmations} more confirmation");
				return;
			}
		}

		private TransactionInformation GetTransactionInformation(ICoin coin, bool withProof)
		{
			var tx = Services.BlockExplorerService
				.GetTransactionsAsync(coin.TxOut.ScriptPubKey, withProof).GetAwaiter().GetResult()
				.FirstOrDefault(t => t.Transaction.Outputs.AsCoins().Any(c => c.Outpoint == coin.Outpoint));
			if(tx == null)
			{
				//In case of reorg, it is possible the transaction is not returned by the wallet anymore.
				//In such case, this will look also in mempool/coinview and try to import the transaction
				tx = Services.BlockExplorerService.GetTransaction(coin.Outpoint.Hash, true);
				if(tx?.MerkleProof != null)
					//No await intended
					Services.BlockExplorerService.TrackPrunedTransactionAsync(tx.Transaction, tx.MerkleProof);
			}
			return tx;
		}

		private FeeRate GetFeeRate()
		{
			return Services.FeeService.GetFeeRateAsync().GetAwaiter().GetResult();
		}

		private void Assert(bool test, string error)
		{
			if(!test)
				throw new PuzzleException(error);
		}
	}
}
