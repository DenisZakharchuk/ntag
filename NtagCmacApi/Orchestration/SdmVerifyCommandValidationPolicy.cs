using System.Globalization;

namespace NtagCmacApi.Orchestration;

/// <summary>
/// Default <see cref="ISdmVerifyCommandValidationPolicy"/>: requires non-empty UID, counter,
/// and CMAC fields, and requires the counter to be a valid hexadecimal string.
/// </summary>
public sealed class SdmVerifyCommandValidationPolicy : ISdmVerifyCommandValidationPolicy
{
    public bool TryValidate(SdmVerifyCommand command, out int counterValue)
    {
        if (string.IsNullOrEmpty(command.Uid) ||
            string.IsNullOrEmpty(command.Counter) ||
            string.IsNullOrEmpty(command.Cmac) ||
            !int.TryParse(command.Counter, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out counterValue))
        {
            counterValue = 0;
            return false;
        }

        return true;
    }
}
