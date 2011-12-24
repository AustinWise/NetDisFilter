using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Reflection;
using System.IO.Compression;

namespace NetDisFilter
{
    class LilByteStream
    {
        private readonly MemoryStream mStream;
        private BinaryWriter mWriter;

        public LilByteStream()
        {
            mStream = new MemoryStream(0x100);
            mWriter = new BinaryWriter(mStream);
        }

        public MemoryStream Stream { get { return mStream; } }

        public long Length
        {
            get { return mStream.Length; }
        }

        public void Write(dynamic val)
        {
            mWriter.Write(val);
        }

        public void CloseAndCopy(Stream to)
        {
            mWriter = null;
            var br = new BinaryWriter(to);
            br.Write(mStream.Length);
            mStream.Seek(0, SeekOrigin.Begin);
            mStream.CopyTo(to);
        }

        public override string ToString()
        {
            return string.Format("Length: {0}", mStream.Length);
        }
    }

    class Program
    {
        //const string FILE = @"C:\Users\AustinWise\Documents\Visual Studio 2010\Projects\ConsoleApplication4\ConsoleApplication4\bin\Release\ConsoleApplication4.exe";
        //const string FILE = @"c:\lib\Ninject\2.0\2010-05-28\Ninject.dll";
        const string FILE = @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.ServiceModel.dll";
        static void Main(string[] args)
        {
            var pe = new PeHeaderReader(FILE);
            var head = new CorReader(pe);

            var asm = AssemblyDefinition.ReadAssembly(FILE);
            using (var mappedFile = MemoryMappedFile.CreateFromFile(FILE, FileMode.Open, Guid.NewGuid().ToString(), 0, MemoryMappedFileAccess.Read))
            {
                Process(pe, asm, mappedFile);
            }

            var fatStream = new MemoryStream(0x1000);

            foreach (var s in typeof(Program).GetFields(BindingFlags.NonPublic | BindingFlags.Static)
                .Where(f => f.Name != "fullMethods")
                .Where(f => f.FieldType == typeof(LilByteStream))
                .Select(f => new { Field = f, Stream = (LilByteStream)f.GetValue(null) }))
            {
                var name = s.Field.Name;
                Console.WriteLine("{0}: {1,-10}", name, s.Stream.Length);
                s.Stream.CloseAndCopy(fatStream);
            }

            Console.WriteLine();

            Console.WriteLine("Full Method Copy size: {0}", fullMethods.Length);
            Console.WriteLine("Squished Together size: {0}", fatStream.Length);

            Console.WriteLine();

            var fullSize = CompressStream(fullMethods.Stream, "Full Copy");
            var compressedSize = CompressStream(fatStream, "Sorted");


            Console.WriteLine("Full size:       {0} ({1})", fullSize, (double)fullSize / fullMethods.Length);
            Console.WriteLine("Compressed size: {0} ({1})", compressedSize, (double)compressedSize / fatStream.Length);
            Console.WriteLine("Ratio: {0}", (double)compressedSize / (double)fullSize);
        }

        static long CompressStream(MemoryStream orgStream, string name)
        {
            orgStream.Seek(0, SeekOrigin.Begin);

            var compressedData = new MemoryStream();
            var gzip = new GZipStream(compressedData, CompressionMode.Compress);
            orgStream.CopyTo(gzip);
            gzip.Flush();

            orgStream.Seek(0, SeekOrigin.Begin);

            using (var fs = new FileStream(Path.Combine(@"C:\temp\comptest\", name + ".bin"), FileMode.Create, FileAccess.Write))
            {
                orgStream.CopyTo(fs);
            }

            return compressedData.Length;
        }

        static LilByteStream flags = new LilByteStream();
        static LilByteStream maxStack = new LilByteStream();
        static LilByteStream codeSize = new LilByteStream();
        static LilByteStream localVar = new LilByteStream();

        static LilByteStream exceptionStuff = new LilByteStream();

        static LilByteStream fullMethods = new LilByteStream();

        static LilByteStream opcodes = new LilByteStream();
        static LilByteStream switches = new LilByteStream();
        static LilByteStream sbyteBranch = new LilByteStream();
        static LilByteStream intBranch = new LilByteStream();
        static LilByteStream varIndex = new LilByteStream();
        static LilByteStream argIndex = new LilByteStream();
        static LilByteStream sigToken = new LilByteStream();
        static LilByteStream inlineInt = new LilByteStream();
        static LilByteStream inlieFloat = new LilByteStream();
        static LilByteStream strTokens = new LilByteStream();
        static LilByteStream otherTokens = new LilByteStream();

        private static void Process(PeHeaderReader pe, AssemblyDefinition asm, MemoryMappedFile mappedFile)
        {

            foreach (var m in asm.MainModule.Types.SelectMany(t => t.Methods))
            {
                if (!m.HasBody)
                    continue;
                var body = m.Body;
                //Console.WriteLine("{0,-40}{1:x}{2,10:x}{3,10:x}", m.Name, m.RVA, body.LengthOnDisk, body.IndexAfterCode);

                if (RequiresFatHeader(body))
                {
                    flags.Write(body.Flags);
                    maxStack.Write((UInt16)body.MaxStackSize);
                    codeSize.Write(body.CodeSize);
                    localVar.Write(body.LocalVarToken.ToUInt32());
                }
                else
                {
                    flags.Write((byte)(0x2 | (body.CodeSize << 2)));
                }

                foreach (var instr in body.Instructions)
                {
                    if (instr.OpCode.Size == 1)
                        opcodes.Write(instr.OpCode.Op2);
                    else
                    {
                        opcodes.Write(instr.OpCode.Op1);
                        opcodes.Write(instr.OpCode.Op2);
                    }

                    var operand = instr.Operand;
                    switch (instr.OpCode.OperandType)
                    {
                        case OperandType.InlineSwitch:
                            {
                                var targets = (Instruction[])operand;
                                switches.Write(targets.Length);
                                for (int i = 0; i < targets.Length; i++)
                                    switches.Write(GetTargetOffset(body, targets[i]));
                                break;
                            }
                        case OperandType.ShortInlineBrTarget:
                            {
                                var target = (Instruction)operand;
                                sbyteBranch.Write((sbyte)GetTargetOffset(body, target));
                                break;
                            }
                        case OperandType.InlineBrTarget:
                            {
                                var target = (Instruction)operand;
                                intBranch.Write(GetTargetOffset(body, target));
                                break;
                            }
                        case OperandType.ShortInlineVar:
                            varIndex.Write((byte)((VariableDefinition)operand).Index);
                            break;
                        case OperandType.ShortInlineArg:
                            varIndex.Write((byte)GetParameterIndex(body, (ParameterDefinition)operand));
                            break;
                        case OperandType.InlineVar:
                            varIndex.Write((short)((VariableDefinition)operand).Index);
                            break;
                        case OperandType.InlineArg:
                            varIndex.Write((short)GetParameterIndex(body, (ParameterDefinition)operand));
                            break;
                        case OperandType.InlineSig:
                            sigToken.Write(((CallSite)operand).MetadataToken.ToUInt32());
                            break;
                        case OperandType.ShortInlineI:
                            if (instr.OpCode == OpCodes.Ldc_I4_S)
                                inlineInt.Write((sbyte)operand);
                            else
                                inlineInt.Write((byte)operand);
                            break;
                        case OperandType.InlineI:
                            inlineInt.Write((int)operand);
                            break;
                        case OperandType.InlineI8:
                            inlineInt.Write((long)operand);
                            break;
                        case OperandType.ShortInlineR:
                            inlieFloat.Write((float)operand);
                            break;
                        case OperandType.InlineR:
                            inlieFloat.Write((double)operand);
                            break;
                        case OperandType.InlineString:
                            strTokens.Write(instr.StringOperandToken.ToUInt32());
                            break;
                        case OperandType.InlineType:
                        case OperandType.InlineField:
                        case OperandType.InlineMethod:
                        case OperandType.InlineTok:
                            otherTokens.Write(((IMetadataTokenProvider)operand).MetadataToken.ToUInt32());
                            break;
                        case OperandType.InlineNone:
                            break;
                        default:
                            throw new ArgumentException();
                    }
                    //write some code
                }

                using (var mm = mappedFile.CreateViewAccessor(pe.GetFileOffset(m.RVA), body.LengthOnDisk, MemoryMappedFileAccess.Read))
                {
                    for (int i = body.IndexAfterCode; i < body.LengthOnDisk; i++)
                    {
                        exceptionStuff.Write(mm.ReadByte(i));
                    }

                    //do a full copy of the method
                    for (int i = 0; i < body.LengthOnDisk; i++)
                    {
                        fullMethods.Write(mm.ReadByte(i));
                    }
                }
            }
        }



        static bool RequiresFatHeader(Mono.Cecil.Cil.MethodBody body)
        {
            return body.CodeSize >= 64
                || body.InitLocals
                || body.HasVariables
                || body.HasExceptionHandlers
                || body.MaxStackSize > 8;
        }

        static int GetTargetOffset(Mono.Cecil.Cil.MethodBody body, Instruction instruction)
        {
            if (instruction == null)
            {
                var last = body.Instructions[body.Instructions.Count - 1];
                return last.Offset + last.GetSize();
            }

            return instruction.Offset;
        }

        static int GetParameterIndex(Mono.Cecil.Cil.MethodBody body, ParameterDefinition parameter)
        {
            if (body.Method.HasThis)
            {
                if (parameter == body.ThisParameter)
                    return 0;

                return parameter.Index + 1;
            }

            return parameter.Index;
        }
    }
}
