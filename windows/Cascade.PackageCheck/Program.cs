using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
void Require(bool ok, string message) { if (!ok) throw new InvalidDataException(message); }
foreach (var file in args.Take(2))
{
 using var stream = File.OpenRead(file); using var pe = new PEReader(stream);
 Require(pe.PEHeaders.CoffHeader.Machine == Machine.Amd64, "Not an x64 PE: " + file);
 Require(pe.PEHeaders.PEHeader!.Subsystem == Subsystem.WindowsGui, "Not a GUI EXE: " + file);
 Console.WriteLine("PASS Windows x64 GUI PE: " + Path.GetFileName(file));
}
using var input = File.OpenRead(args[2]); using var managed = new PEReader(input);
var metadata = managed.GetMetadataReader(); var data = managed.GetSectionData(managed.PEHeaders.CorHeader!.ResourcesDirectory.RelativeVirtualAddress).GetContent();
byte[] Resource(string name)
{
 foreach (var handle in metadata.ManifestResources)
 {
  var r = metadata.GetManifestResource(handle);
  if (metadata.GetString(r.Name) != name) continue;
  var offset = checked((int)r.Offset); var length = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset,4));
  return data.AsSpan(offset+4,length).ToArray();
 }
 throw new Exception("Missing resource " + name);
}
var brand=Resource("Cascade.Brand.png");
Require(brand.Length>1000,"Installer artwork missing");
if(args.Length>3) Require(SHA256.HashData(brand).SequenceEqual(SHA256.HashData(File.ReadAllBytes(args[3]))),"Installer artwork mismatch");
Console.WriteLine("PASS panda artwork embedded in installer");
var payload = Resource("Cascade.Payload.zip"); var digest = Encoding.UTF8.GetString(Resource("Cascade.Payload.sha256")).Trim();
Require(Convert.ToHexString(SHA256.HashData(payload)).Equals(digest,StringComparison.OrdinalIgnoreCase),"Embedded payload hash mismatch");
Console.WriteLine("PASS embedded installer payload SHA-256");
using var archive = new ZipArchive(new MemoryStream(payload));
Require(archive.GetEntry("Cascade.exe") is not null,"App missing from payload");
Require(archive.Entries.All(e => !e.FullName.StartsWith('/') && !e.FullName.Contains("../") && !e.FullName.Contains("..\\") && !e.FullName.Contains(':')),"Unsafe archive path");
Require(archive.Entries.All(e => !e.FullName.EndsWith(".bpf",StringComparison.OrdinalIgnoreCase) && !e.FullName.EndsWith(".json",StringComparison.OrdinalIgnoreCase)),"Unexpected private profile in installer");
Require(archive.GetEntry("Notices/SSH.NET-LICENSE.txt") is not null,"Notices missing");
Console.WriteLine("PASS complete payload, safe paths, notices, no user VPN profiles");

if(args.Length>5) {
 using var coreInput=File.OpenRead(args[4]);using var corePe=new PEReader(coreInput);
 var coreMetadata=corePe.GetMetadataReader();var coreData=corePe.GetSectionData(corePe.PEHeaders.CorHeader!.ResourcesDirectory.RelativeVirtualAddress).GetContent();
 var matched=false;
 foreach(var handle in coreMetadata.ManifestResources) {
  var resource=coreMetadata.GetManifestResource(handle);if(coreMetadata.GetString(resource.Name)!="Cascade.Security.py")continue;
  var offset=checked((int)resource.Offset);var length=BinaryPrimitives.ReadInt32LittleEndian(coreData.AsSpan(offset,4));
  Require(SHA256.HashData(coreData.AsSpan(offset+4,length)).SequenceEqual(SHA256.HashData(File.ReadAllBytes(args[5]))),"Security controller resource differs from source");matched=true;
 }
 Require(matched,"Security controller resource missing");Console.WriteLine("PASS current shared security controller embedded in core");
}
