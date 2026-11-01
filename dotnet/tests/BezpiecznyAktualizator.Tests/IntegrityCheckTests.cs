using BezpiecznyAktualizator.Core.Security;

namespace BezpiecznyAktualizator.Tests;

public class IntegrityCheckTests
{
    private const string Thumb = "B4EDE431D9E7C1ABC1F5C78AD9DDC0DC08CF0327";

    [Fact]
    public void UnsignedFileIsRejected() =>
        Assert.NotNull(IntegrityCheck.Problem(new SignatureInfo(SignatureState.Unsigned, 0, ""), "", Thumb));

    [Fact]
    public void TamperedFileIsRejected() =>
        Assert.NotNull(IntegrityCheck.Problem(new SignatureInfo(SignatureState.Invalid, unchecked((int)0x80096010), "x"), Thumb, Thumb));

    [Fact]
    public void OtherSignerIsRejected() =>
        Assert.NotNull(IntegrityCheck.Problem(new SignatureInfo(SignatureState.Valid, 0, "x"), new string('A', 40), Thumb));

    [Theory]
    [InlineData(SignatureState.Valid)]
    [InlineData(SignatureState.Unknown)]
    public void ExpectedSignerIsAcceptedEvenWhenRootIsUntrusted(SignatureState state) =>
        Assert.Null(IntegrityCheck.Problem(new SignatureInfo(state, 0, "x"), Thumb.ToLowerInvariant(), Thumb));

    [Fact]
    public void AnySignerIsAcceptedWhenNoneIsExpected() =>
        Assert.Null(IntegrityCheck.Problem(new SignatureInfo(SignatureState.Valid, 0, "x"), new string('A', 40), ""));

    [Fact]
    public void SignerThumbprintOfUnsignedFileIsEmpty()
    {
        var path = Path.GetTempFileName();
        try { Assert.Equal("", Authenticode.SignerThumbprint(path)); }
        finally { File.Delete(path); }
    }
}
