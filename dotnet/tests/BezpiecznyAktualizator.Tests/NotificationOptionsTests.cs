using System.Text.Json;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Tests;

public class NotificationOptionsTests
{
    [Fact]
    public void NotificationSecretsRoundTripEncryptedAndAreNotSerializedAsPlaintext()
    {
        const string webhook = "https://tenant.webhook.office.com/webhookb2/private-token";
        const string password = "smtp-secret";
        var options = new NotificationOptions();
        options.SetTeamsWebhook(webhook);
        options.SetSmtpPassword(password);

        var serialized = JsonSerializer.Serialize(options);
        Assert.DoesNotContain(webhook, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(password, serialized, StringComparison.Ordinal);
        Assert.Equal(webhook, options.GetTeamsWebhook());
        Assert.Equal(password, options.GetSmtpPassword());
    }
}
