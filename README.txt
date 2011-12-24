The compression pre-processor in kkrunchy[1] is quite fascinating.  I'm
exploring here whether something like that would work on .NET assemblies.  This
is prototype-quality code, so watch out.

I tested the prototype by compressing System.ServiceModel.dll in .NET 4, which
is the largest managed code DLL in .NET 4.  After being run through the prototype,
it's 1.5MB of IL compresses to 95% of the size of the unprocessed code.  That's
with the built in GZip of .NET.  With 7-zip's LZMA on ultra setting, it is 92%
of the size.  Of course this is only compressing the IL, the metadata is even
larger.  Some processing of the metadata will probably be need to save more than
the 37KB this saves of a 5.8MB DLL.

The PE opening code is mostly from a blog somewhere.  I need to sort out the
license.

[1] http://fgiesen.wordpress.com/2011/01/24/x86-code-compression-in-kkrunchy/
