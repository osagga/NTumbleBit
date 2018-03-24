﻿using NBitcoin;
using NBitcoin.DataEncoders;
using NTumbleBit.BouncyCastle.Crypto.Engines;
using NTumbleBit.BouncyCastle.Crypto.Parameters;
using NTumbleBit.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NTumbleBit
{
	public class PuzzleValue : IBitcoinSerializable
	{
		internal BigInteger _Value;
		public PuzzleValue()
		{

		}
		public PuzzleValue(byte[] z)
		{
			if(z == null)
				throw new ArgumentNullException(nameof(z));
			_Value = new BigInteger(1, z);
		}
		internal PuzzleValue(BigInteger z)
		{
            _Value = z ?? throw new ArgumentNullException(nameof(z));
		}

		public byte[] ToBytes()
		{
			return _Value.ToByteArrayUnsigned();
		}

		public override bool Equals(object obj)
		{
			PuzzleValue item = obj as PuzzleValue;
			if(item == null)
				return false;
			return _Value.Equals(item._Value);
		}
		public static bool operator ==(PuzzleValue a, PuzzleValue b)
		{
			if(ReferenceEquals(a, b))
				return true;
			if(((object)a == null) || ((object)b == null))
				return false;
			return a._Value.Equals(b._Value);
		}

		public PuzzleSolution Solve(RsaKey key)
		{
			if(key == null)
				throw new ArgumentNullException(nameof(key));
			return key.SolvePuzzle(this);
		}

		public static bool operator !=(PuzzleValue a, PuzzleValue b)
		{
			return !(a == b);
		}

		public override int GetHashCode()
		{
			return _Value.GetHashCode();
		}

		public override string ToString()
		{
			return Encoders.Hex.EncodeData(ToBytes());
		}

		public Puzzle WithRsaKey(RsaPubKey key)
		{
			return new Puzzle(key, this);
		}

		public void ReadWrite(BitcoinStream stream)
		{
			stream.ReadWriteC(ref _Value);
		}
	}
}
