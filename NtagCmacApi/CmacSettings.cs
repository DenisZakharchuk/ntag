using Ntag424.Cmac;

namespace NtagCmacApi;

/// <summary>
/// Bound from the "Ntag:MacMessagePolicy" configuration section (mirrors its "Type"
/// sub-key). A thin app-level adapter POCO - kept separate from Ntag424Cmac's own
/// <see cref="CmacOptions"/> so config binding (automatic enum parsing, live-reload via
/// <see cref="Microsoft.Extensions.Options.IOptionsMonitor{TOptions}"/>) stays decoupled
/// from the library's own composition-root shape.
/// </summary>
public sealed class MacMessagePolicySettings
{
    public const string SectionName = "Ntag:MacMessagePolicy";

    public MacMessagePolicyKind Type { get; set; } = MacMessagePolicyKind.EmptyMessage;
}

/// <summary>
/// Bound from the "Ntag:CounterCodec" configuration section (mirrors its "Type" sub-key).
/// See <see cref="MacMessagePolicySettings"/> remarks.
/// </summary>
public sealed class CounterCodecSettings
{
    public const string SectionName = "Ntag:CounterCodec";

    public CounterCodecKind Type { get; set; } = CounterCodecKind.LiteralHex;
}
