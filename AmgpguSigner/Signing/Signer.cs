using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace AmgpguSigner.Signing
{
  public class Signer
  {
    public static byte[] SignAsCmsWithPKCS7(byte[] data, X509Certificate2 certificate, ContainerPassword passwordContainer = null)
    {
      Oid oid = new Oid("1.2.840.113549.1.7", "PKCS 7");
      var privateKey = GetGost3410_2012_256CryptoServiceProvider(certificate, passwordContainer);
      CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate, privateKey);
      SignedCms signedMessage = new SignedCms(new ContentInfo(oid, data), true);
      signedMessage.ComputeSignature(signer);
      byte[] signedData = signedMessage.Encode();

      return signedData;
    }


    private static Gost3410_2012_256CryptoServiceProvider GetGost3410_2012_256CryptoServiceProvider(X509Certificate2 certificate, ContainerPassword passwordContainer = null)
    {
      var privateKey = certificate.PrivateKey as Gost3410_2012_256CryptoServiceProvider;
      if (passwordContainer != null)
      {
        privateKey.SetContainerPassword(GetSecureString(passwordContainer.ToString()));
      }

      return privateKey;
    }

    private static SecureString GetSecureString(string password)
    {
      var secureString = new SecureString();

      foreach (char c in password)
      {
        secureString.AppendChar(c);
      }

      return secureString;
    }
  }
}
