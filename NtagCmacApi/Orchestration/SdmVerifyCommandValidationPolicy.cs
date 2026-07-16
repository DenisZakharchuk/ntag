using System.Globalization;

namespace NtagCmacApi.Orchestration;

/// <summary>
/// Default <see cref="ISdmVerifyCommandValidationPolicy"/>: requires non-empty UID, counter,
/// CMAC, and company code fields, and requires the counter to be a valid hexadecimal string.
/// </summary>
public sealed class SdmVerifyCommandValidationPolicy : ISdmVerifyCommandValidationPolicy
{
    public bool TryValidate(SdmVerifyCommand command, out int counterValue)
    {
        if (string.IsNullOrEmpty(command.Uid) ||
            string.IsNullOrEmpty(command.Counter) ||
            string.IsNullOrEmpty(command.Cmac) ||
            string.IsNullOrEmpty(command.CompanyCode) ||
            !int.TryParse(command.Counter, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out counterValue))
        {
            counterValue = 0;
            return false;
        }

        return true;
    }
}
