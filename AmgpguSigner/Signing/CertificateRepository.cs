using System.Security.Cryptography.X509Certificates;

namespace AmgpguSigner.Signing
{
  public class CertificateRepository
  {
    public static X509Certificate2 GetCertificateByThumbprint(string thumbprint, StoreName storeName, StoreLocation storeLocation)
    {
      X509Store store = new X509Store(storeName, storeLocation);
      store.Open(OpenFlags.ReadOnly);
      var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
      store.Close();
      return certs[0];
    }
  }
}
