﻿using NTumbleBit.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NTumbleBit.ClassicTumbler.CLI
{
	public class CommandLineParser
	{

		private readonly string[] _Args;
		public string[] Args
		{
			get
			{
				return _Args;
			}
		}
		public CommandLineParser(string[] args)
		{
            _Args = args ?? throw new ArgumentNullException(nameof(args));
		}

		public bool GetBool(string key)
		{
			return Args.Contains(key);
		}

		public string GetRequiredString(string key)
		{
			var start = key + "=";
			foreach(var arg in Args)
			{
				if(arg.StartsWith(start, StringComparison.Ordinal))
				{
					return arg.Substring(start.Length);
				}
			}
			throw new ConfigException("Required command line " + key + " not found");
		}
	}
}
