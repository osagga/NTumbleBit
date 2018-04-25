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
			
			// TODO: Figure out a better way for Bob and Alice to set these parameters.
			// NOTE: For testing proposes, we can tweek the values from here.
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
					// TODO[READY]
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
					// TODO[READY]
						if(Status == PaymentStateMachineStatus.Registered)
						{
							// TODO[READY]
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
                            catch (NotEnoughFundsException ex)
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
							// All the Escrowed amount, and not give any change to the Tumbler.
							var redeemTx = SolverClientSession.CreateRedeemTransaction(feeRate);
							Tracker.AddressCreated(cycle.Start, TransactionType.ClientRedeem, redeemDestination, correlation);

							//redeemTx does not be to be recorded to the tracker, this is TrustedBroadcastService job

							Services.BroadcastService.BroadcastAsync(clientEscrowTx).GetAwaiter().GetResult();

							Services.TrustedBroadcastService.Broadcast(cycle.Start, TransactionType.ClientRedeem, correlation, redeemTx);
							Status = PaymentStateMachineStatus.ClientChannelBroadcasted;
						}
						else if(Status == PaymentStateMachineStatus.ClientChannelBroadcasted)
						{
							// TODO[READY]
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
							// TODO[READY]
							
							// NOTE: After this stage, the Tumbler would have escrowed the requested payments
							bob = Runtime.CreateTumblerClient(cycle.Start, Identity.Bob);
							Logs.Client.LogInformation("Begin ask to open the channel...");
							//Client asks the Tumbler to make a channel
							
							var bobEscrowInformation = ClientChannelNegotiation.GetOpenChannelRequest();
							
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
                            
							/*
								NOTE [DESIGN]:
									We can either pass the puzzles from Alice to Bob through:
										- "ClientChannelNegotiation.ReceivePuzzles" funtion that I defined.
											The function will save the list of puzzles in the internalState of the ClientChannelNegotiation
											And then in AcceptPuzzle (from the ClientSolver), we can pass the index of the puzzle and get
											the corresponding puzzle from this internal state.
										- The other approach is that we can just save the list of puzzles internally in the SolverClientSession.Parameters
											And then AcceptPuzzle will internally refrence this list with the CurrentPuzzleNum.
							
							 */
							
							SolverClientSession.Parameters.Puzzles = puzzles;
							// ClientChannelNegotiation.ReceivePuzzles(puzzles);
							
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
							// TODO[DESIGN]: Need to figure out wether we keep this or change the part about counting bobs based on the outputvalue.
							CheckTumblerChannelSecured(cycle);
						}
						//No "else if" intended
						if(Status == PaymentStateMachineStatus.TumblerChannelSecured)
						{
                            // Start of a puzzle solving session.
                            /*
							NOTE:
								- The logic here is that, every call to "update" with the state "TumblerChannelSecured" will solve
									a new puzzle from the stored puzzles we got from Bob (incrementally).
								- Alice can only exit or terminate the solver protocol through:
									- Reaching the max number of puzzles she can solve given "AliceRequestedPaymentsCount"
										- In this case, the "Status" will change to "PuzzleSolutionObtained"
											- [DESIGN] I'm not sure if I should introduce a new Status for this case.
									- Willingly, Alice decides to stop solving puzzles as long as she didn't reach the limit.
										- In this case, the "Status" will change to "PuzzleSolutionObtained" and any further calls 
											to update will just skip solving a new puzzle and wait till the cashout phase.
									- The Tumbler is Uncooperative (didn't give the solutions back).
										- In this case, the "Status" will change to "UncooperativeTumbler" and we would just terminate
											the current puzzle solving on the i_th puzzle and wait till we get to the cashout phase and
											Try to acquire the solution from the T_solve from the Blockchain to the i_th puzzle.
												- Otherwise, we would just cashout the 
								
							 */

                            // TODO [DONE]: This is the number of the puzzle we are currently solving.
                            if (!SolverClientSession.CanSolvePuzzles())
                            {
                                Logs.Client.LogDebug("Tumbler doesn't allow solving more puzzles, the payment is wasted");
                                Status = PaymentStateMachineStatus.Wasted;
                                break;
                            }else{
                                SolverClientSession.AcceptBobPuzzle();
                            }
                            
                            alice = Runtime.CreateTumblerClient(cycle.Start, Identity.Alice);
							Logs.Client.LogDebug("Starting the puzzle solver protocol...");
                            // TODO: We might need to manually set the InternalState of the SolverClient to "WaitingPuzzle"
                            // so that we can solve future puzzles without violating assertions in the client.

                            // NOTE: This function assumes that InternalState.CurrentPuzzleNum is the puzzle that we need to get the solution for (Related to the deign note above).
                            SolverClientSession.AcceptPuzzle();

							var puzzles = SolverClientSession.GeneratePuzzles();
                            // TODO[DONE]: The tumbler should start the counter here.
                            // Note: Every call to this function will be considered as a new puzzle solving request, and will cost one
                            // more payment than the previous one.
                            try
                            {
                                alice.BeginSolvePuzzles(SolverClientSession.Id, puzzles);
                            }
                            catch (Exception ex) when (ex.Message.IndexOf("exceed-puzzle-count", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                Logs.Client.LogDebug(new EventId(), ex, "Tumbler doesn't allow solving more puzzles, the payment is wasted");
                                Status = PaymentStateMachineStatus.Wasted;
                                break;
                            }
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

                            // NOTE: This generates a new address that Alice can receive the change back on.
                            var aliceCashoutDestination = Services.WalletService.GenerateAddressAsync().GetAwaiter().GetResult().ScriptPubKey;
							Tracker.AddressCreated(cycle.Start, TransactionType.TumblerCashout, aliceCashoutDestination, correlation);
							
							// NOTE: It seems like this creates and signs T_puzzle
							// TODO[DESIGN][DONE]: Solve a design decision inside.
							var offerSignature = SolverClientSession.SignOffer(offerInformation, aliceCashoutDestination);
							
							// NOTE: It seems like this function creates the redeem transaction for T_puzzle
							// TODO[DONE]: finish some work inside.
							var offerRedeem = SolverClientSession.CreateOfferRedeemTransaction(feeRate);
							
							//May need to find solution in the fulfillment transaction
							Services.BlockExplorerService.TrackAsync(offerRedeem.PreviousScriptPubKey).GetAwaiter().GetResult();
							Tracker.AddressCreated(cycle.Start, TransactionType.ClientOfferRedeem, SolverClientSession.GetInternalState().RedeemDestination, correlation);

                            Services.TrustedBroadcastService.RemoveBroadcast(SolverClientSession.GetInternalState().Tx_offerRedeem);
                            // TODO: It seems like offerRedeem is broadcasted instintally, so if we would want to lock it, when would we do that?
                            Services.TrustedBroadcastService.Broadcast(cycle.Start, TransactionType.ClientOfferRedeem, correlation, offerRedeem);
                            SolverClientSession.SetofferRedeemTransaction(offerRedeem.Transaction);

                            try
							{
								solutionKeys = alice.FulfillOffer(SolverClientSession.Id, offerSignature, aliceCashoutDestination);
								SolverClientSession.CheckSolutions(solutionKeys);
								var tumblingSolution = SolverClientSession.GetSolution();
								var transaction = PromiseClientSession.GetSignedTransaction(tumblingSolution, SolverClientSession.GetInternalState().CurrentPuzzleNum);
								Logs.Client.LogDebug("Got puzzle solution cooperatively from the tumbler");
                                Status = PaymentStateMachineStatus.PuzzleSolutionObtained;
                                // TODO: Before we broadcast here, we need to remove the previous broadcast request so that we gurantee that Bob will get the higher payment transaction.
                                //NOTE: Bob would cashout only in the cashOut phase, not in this phase.
                                Services.TrustedBroadcastService.Broadcast(cycle.Start, TransactionType.TumblerCashout, correlation, new TrustedBroadcastRequest()
								{
									BroadcastAt = cycle.GetPeriods().ClientCashout.Start,
									Transaction = transaction
								});

                                if (Cooperative)
								{
                                    // If Alice is Cooperative, we make T_cash and give it to the Tumbler
									try
									{
										// No need to await for it, it is a just nice for the tumbler (we don't want the underlying socks connection cut before the escape key is sent)
                                        // TODO[DONE]: Figure out the last parameter here, the Tumbler probably have to provide a cashout address with sending back the offer information
										var signature = SolverClientSession.SignEscape(aliceCashoutDestination, offerInformation.EscapeCashout, offerInformation.Fee);
										alice.GiveEscapeKeyAsync(SolverClientSession.Id, signature).GetAwaiter().GetResult();
									}
                                    //NOTE: Since we are planning to send future escape transactions, if one failes, then we abort the Solver Protocol.
									catch(Exception ex)
                                    {
                                        Logs.Client.LogWarning(new EventId(), ex, "Exception while giving the escape key");
                                        Status = PaymentStateMachineStatus.PuzzleSolutionObtained;
                                        Logs.Client.LogDebug("Puzzle solver protocol ended...");
                                        break;
                                    }
									Logs.Client.LogInformation("Gave escape signature to the tumbler");
                                    
                                    if (SolverClientSession.CanSolvePuzzles())
                                    {
                                        // NOTE: If we want to solve an additional puzzle, we reset the Solver session state and we also reset the PaymentStateMachineStatus to go back up.
                                        SolverClientSession.AllowPuzzleRequest();
                                        Status = PaymentStateMachineStatus.TumblerChannelSecured;
                                    }
                                    else
                                    {
                                        // NOTE: This is the case that we have already solved all the puzzles, or just cant solve anymore.                                        
                                        Logs.Client.LogDebug("Puzzle solver protocol ended...");
                                    }
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
                                //NOTE[DESIGN]: If the Tumbler behaves Uncooperative, then we end the solver protocol and just stop solving future puzzles.
								Status = PaymentStateMachineStatus.PuzzleSolutionObtained;
								var tumblingSolution = SolverClientSession.GetSolution();
								var transaction = PromiseClientSession.GetSignedTransaction(tumblingSolution, SolverClientSession.GetInternalState().CurrentPuzzleNum);
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
						So we can't use the transaction amount as a filter, maybe use something else? (PubKey of the Tumbler? If it's the same for each Bob?)
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
