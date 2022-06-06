namespace AmgpguSigner.Signing
{
  public class ContainerPassword
  {
    private readonly string _password;

    public ContainerPassword(string password)
    {
      _password = password;
    }

    public override string ToString()
    {
      return this._password;
    }
  }
}
