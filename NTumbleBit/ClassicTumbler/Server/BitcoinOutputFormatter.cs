using Microsoft.AspNetCore.Mvc.Formatters;
using System.Reflection;
using NBitcoin;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace NTumbleBit.ClassicTumbler.Server
{
	public class BitcoinOutputFormatter : IOutputFormatter
	{
		public bool CanWriteResult(OutputFormatterCanWriteContext context)
		{
			// TODO: make this check such that it can detect 2D arrays and returns 'true' if they're 'IBitcoinSerializable'
			return (typeof(IBitcoinSerializable).GetTypeInfo().IsAssignableFrom(context.ObjectType)) ||
				(context.ObjectType.IsArray && typeof(IBitcoinSerializable).GetTypeInfo().IsAssignableFrom(context.ObjectType.GetTypeInfo().GetElementType())) ||
				(context.ObjectType.IsArray && context.ObjectType.GetTypeInfo().GetElementType().IsArray && typeof(IBitcoinSerializable).GetTypeInfo().IsAssignableFrom(context.ObjectType.GetTypeInfo().GetElementType().GetElementType()));
		}

		public Task WriteAsync(OutputFormatterWriteContext context)
		{
			// TODO: The problem is here!
			var obj = context.Object;
			if(context.ObjectType.IsArray)
			{
				// TODO:  Handle the case of 2D arrays here!!!
				Type arrayWrapper;
				if (context.ObjectType.GetTypeInfo().GetElementType().IsArray){
					arrayWrapper = typeof(TwoDArrayWrapper<>).GetTypeInfo().MakeGenericType(context.ObjectType.GetElementType().GetElementType());
				}else{
					arrayWrapper = typeof(ArrayWrapper<>).GetTypeInfo().MakeGenericType(context.ObjectType.GetElementType());
				}
				obj = Activator.CreateInstance(arrayWrapper, context.Object);
			}
			var bytes = ((IBitcoinSerializable)obj).ToBytes();
			context.HttpContext.Response.StatusCode = 200;
			return context.HttpContext.Response.Body.WriteAsync(bytes, 0, bytes.Length);
		}
	}
}
