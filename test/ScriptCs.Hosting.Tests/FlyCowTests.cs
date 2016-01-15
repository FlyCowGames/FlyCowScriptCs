using System;
using NUnit.Framework;

namespace ScriptCs.Hosting.Tests
{
    [TestFixture]
    public class FlyCowTests
    {
        [Test]
        public void EncryptPassword()
        {
            IEncryptionProvider cp = new EncryptionProvider(new DataEncoder());
            var p = cp.Encript("fly99cow!", DataUtil.HexStringToBytes("0x7B2566EFE30E11CCAC515B0D256AE25FC5D048D6A199CCD8A0640604744DB66123B7B150E626D3EC4E508A0565532F7B5446BE8E82DCDB3D0BD0864FA4CCD5EA"));
            Console.WriteLine(p);
        }
    }
}