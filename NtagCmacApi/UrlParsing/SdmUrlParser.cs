using System;
using System.Collections.Generic;
using NtagCmacApi.Orchestration;

namespace NtagCmacApi.UrlParsing;

/// <summary>
/// Default <see cref="ISdmUrlParser"/>: extracts <c>uid</c>/<c>ctr</c>/<c>mac</c> query
/// parameters (case-insensitive names), and computes the AN12196 Table 5 mirrored-data
/// message as the literal query text from right after <c>?</c> through and including the
/// literal <c>mac=</c> text - i.e. the byte range NXP calls
/// <c>SDMMACInputOffset..SDMMACOffset</c>, confirmed correct for at least one real
/// captured tag read (see repo memory notes / <c>RealWorldTable5NumericCounterVerificationTests</c>).
///
/// This convention (mirrored data = everything up to and including "mac=") is one
/// specific, confirmed case, not a universal guarantee for every possible tag
/// provisioning - a deployment using a different <c>SDMMACInputOffset</c>/<c>SDMMACOffset</c>
/// would need a different extraction rule.
/// </summary>
public sealed class SdmUrlParser : ISdmUrlParser
{
    private const string MacParamPrefix = "mac=";

    public SdmVerifyCommand Parse(string url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out Uri? uri))
        {
            return new SdmVerifyCommand(string.Empty, string.Empty, string.Empty, string.Empty);
        }

        string query = uri.Query.TrimStart('?');
        IReadOnlyDictionary<string, string> parameters = ParseQuery(query);

        string uid = parameters.GetValueOrDefault("uid", string.Empty);
        string counter = parameters.GetValueOrDefault("ctr", string.Empty);
        string cmac = parameters.GetValueOrDefault("mac", string.Empty);

        int macIndex = query.IndexOf(MacParamPrefix, StringComparison.OrdinalIgnoreCase);
        string mirroredData = macIndex >= 0 ? query[..(macIndex + MacParamPrefix.Length)] : string.Empty;

        return new SdmVerifyCommand(uid, counter, cmac, mirroredData);
    }

    private static IReadOnlyDictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] pair = part.Split('=', 2);
            string key = Uri.UnescapeDataString(pair[0]);
            string value = pair.Length > 1 ? Uri.UnescapeDataString(pair[1]) : string.Empty;
            result[key] = value;
        }
        return result;
    }
}
