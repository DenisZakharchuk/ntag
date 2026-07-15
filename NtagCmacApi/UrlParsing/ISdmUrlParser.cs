using NtagCmacApi.Orchestration;

namespace NtagCmacApi.UrlParsing;

/// <summary>
/// Parses a raw SDM URL (e.g. as scanned directly from an NTAG 424 DNA tag) into a
/// <see cref="SdmVerifyCommand"/>, so callers can submit the exact URL text instead of
/// pre-splitting it into uid/counter/cmac/mirrored-data fields themselves.
///
/// On any parse failure (malformed URL, missing required query parameters), returns a
/// command with empty fields rather than throwing - the existing
/// <see cref="ISdmVerifyCommandValidationPolicy"/> already rejects empty fields as
/// <see cref="SdmVerificationOutcome.MalformedRequest"/>, so failure handling stays
/// centralized in one place instead of being duplicated here.
/// </summary>
public interface ISdmUrlParser
{
    SdmVerifyCommand Parse(string url);
}
