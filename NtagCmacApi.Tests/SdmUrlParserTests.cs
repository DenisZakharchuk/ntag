using NtagCmacApi.Orchestration;
using NtagCmacApi.UrlParsing;
using Xunit;

namespace NtagCmacApi.Tests;

public class SdmUrlParserTests
{
    private static readonly ISdmUrlParser Parser = new SdmUrlParser();

    [Fact]
    public void Parse_TypicalSdmUrl_ExtractsUidCounterCmacAndMirroredData()
    {
        const string url = "https://example.com/?serial=11111111&uid=04B43132502390&ctr=000001&mac=E7D76C550FF1755B";

        SdmVerifyCommand command = Parser.Parse(url);

        Assert.Equal("04B43132502390", command.Uid);
        Assert.Equal("000001", command.Counter);
        Assert.Equal("E7D76C550FF1755B", command.Cmac);
        Assert.Equal("serial=11111111&uid=04B43132502390&ctr=000001&mac=", command.MirroredData);
    }

    [Fact]
    public void Parse_PlainTable4Url_NoExtraFields_MirroredDataStillComputed()
    {
        const string url = "https://example.com/tap?uid=04A1B2C3D4E5F6&ctr=000001&mac=9130AE6B05189C97";

        SdmVerifyCommand command = Parser.Parse(url);

        Assert.Equal("04A1B2C3D4E5F6", command.Uid);
        Assert.Equal("000001", command.Counter);
        Assert.Equal("9130AE6B05189C97", command.Cmac);
        Assert.Equal("uid=04A1B2C3D4E5F6&ctr=000001&mac=", command.MirroredData);
    }

    [Fact]
    public void Parse_QueryParamNamesAreCaseInsensitive()
    {
        const string url = "https://example.com/?UID=04B43132502390&CTR=000001&MAC=E7D76C550FF1755B";

        SdmVerifyCommand command = Parser.Parse(url);

        Assert.Equal("04B43132502390", command.Uid);
        Assert.Equal("000001", command.Counter);
        Assert.Equal("E7D76C550FF1755B", command.Cmac);
    }

    [Fact]
    public void Parse_MalformedUrl_ReturnsEmptyCommand()
    {
        SdmVerifyCommand command = Parser.Parse("not a url");

        Assert.Equal(string.Empty, command.Uid);
        Assert.Equal(string.Empty, command.Counter);
        Assert.Equal(string.Empty, command.Cmac);
        Assert.Equal(string.Empty, command.MirroredData);
    }

    [Fact]
    public void Parse_EmptyString_ReturnsEmptyCommand()
    {
        SdmVerifyCommand command = Parser.Parse("");

        Assert.Equal(string.Empty, command.Uid);
    }

    [Fact]
    public void Parse_MissingMacParam_MirroredDataIsEmpty()
    {
        const string url = "https://example.com/?uid=04B43132502390&ctr=000001";

        SdmVerifyCommand command = Parser.Parse(url);

        Assert.Equal("04B43132502390", command.Uid);
        Assert.Equal(string.Empty, command.Cmac);
        Assert.Equal(string.Empty, command.MirroredData);
    }

    [Fact]
    public void Parse_MissingUidOrCounter_ReturnsEmptyForThoseFields()
    {
        const string url = "https://example.com/?mac=E7D76C550FF1755B";

        SdmVerifyCommand command = Parser.Parse(url);

        Assert.Equal(string.Empty, command.Uid);
        Assert.Equal(string.Empty, command.Counter);
        Assert.Equal("E7D76C550FF1755B", command.Cmac);
    }
}
