﻿using NBitcoin;
using System;

namespace NTumbleBit.PuzzlePromise
{
    public class ServerCommitmentsProof : IBitcoinSerializable
    {
        public ServerCommitmentsProof()
        {

        }
        public ServerCommitmentsProof(PuzzleSolution[][] solutions, Quotient[][] quotients)
        {
            FakeSolutions = solutions ?? throw new ArgumentNullException(nameof(solutions));
            Quotients = quotients ?? throw new ArgumentNullException(nameof(quotients));
        }

        PuzzleSolution[][] _FakeSolutions;
        public PuzzleSolution[][] FakeSolutions
        {
            get
            {
                return _FakeSolutions;
            }
            set
            {
                _FakeSolutions = value;
            }
        }


        Quotient[][] _Quotients;
        public Quotient[][] Quotients
        {
            get
            {
                return _Quotients;
            }
            set
            {
                _Quotients = value;
            }
        }

        public void ReadWrite(BitcoinStream stream)
        {
            stream.ReadWriteC(ref _FakeSolutions);
            stream.ReadWriteC(ref _Quotients);
        }
    }
}
