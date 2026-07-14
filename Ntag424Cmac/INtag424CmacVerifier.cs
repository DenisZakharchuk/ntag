namespace Ntag424.Cmac;

/// <summary>
/// Verifies that a received SDM CMAC matches the one a genuine NTAG 424 DNA tag would
/// have produced for a given UID, read counter, and master key.
/// </summary>
public interface INtag424CmacVerifier
{
    bool Verify(in Ntag424SdmCmacRequest request);
}
