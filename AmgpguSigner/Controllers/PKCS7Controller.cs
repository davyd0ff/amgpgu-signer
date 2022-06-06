using AmgpguSigner.Signing;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AmgpguSigner.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class PKCS7Controller : ControllerBase
  {
    private readonly X509Certificate2 _certificate;
    private readonly ContainerPassword _containerPassword;

    public PKCS7Controller(X509Certificate2 certificate, ContainerPassword containerPassword)
    {
      this._certificate = certificate;
      this._containerPassword = containerPassword;
    }

    [HttpPost("[action]/{message}")]
    public string Sign(string message)
    {
      var messageToBytes = Encoding.UTF8.GetBytes(message);
      var signedMessage = Signer.SignAsCmsWithPKCS7(messageToBytes, this._certificate, this._containerPassword);
      return Convert.ToBase64String(signedMessage);
    }
  }
}
