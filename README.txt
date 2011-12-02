The compression pre-processor in kkrunchy[1] is quite fascinating.  I'm
exploring here whether something like that would work on .NET assemblies.

Right now this is just code for opening up PE files and the .NET meta data
streams.  The PE opening code is mostly from a blog somewhere.  I
need to sort of the license.

It is possible that this technique will not be that helpful.  The .NET
metadata streams are larger than the IL code generally.  The tables in
the #~ stream look like they could benefit from the DisFilter technique,
but the #US and #Strings streams are still pretty big.  So we'll see.

[1] http://fgiesen.wordpress.com/2011/01/24/x86-code-compression-in-kkrunchy/
