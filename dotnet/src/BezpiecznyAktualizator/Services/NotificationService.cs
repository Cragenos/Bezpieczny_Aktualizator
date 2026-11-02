using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.Mail;
using System.Text.Json;
using BezpiecznyAktualizator.Core.Localization;

namespace BezpiecznyAktualizator.Services;

public static class NotificationService
{
    private static readonly HttpClient Http = new(new SocketsHttpHandler { AllowAutoRedirect = false })
    {
        Timeout = TimeSpan.FromSeconds(15),
    };
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static async Task<IReadOnlyList<string>> SendAsync(NotificationOptions options, string summary,
        CancellationToken ct = default)
    {
        options.Normalize();
        var errors = new List<string>();
        if (!options.Enabled) return errors;

        if (options.TeamsEnabled)
        {
            try
            {
                var webhook = options.GetTeamsWebhook();
                if (webhook is null || !TryTeamsWebhook(webhook, out var uri))
                    throw new InvalidOperationException(L.T("Nie skonfigurowano prawidłowego adresu HTTPS webhooka Teams."));
                using var response = await Http.PostAsJsonAsync(uri, new { text = summary }, JsonOptions, ct);
                if (!response.IsSuccessStatusCode)
                    throw new HttpRequestException(L.F("Webhook Teams zwrócił kod HTTP {0}.", (int)response.StatusCode));
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException or
                                           UriFormatException or System.Security.Cryptography.CryptographicException or FormatException or
                                           System.ComponentModel.Win32Exception)
            {
                errors.Add(L.F("Powiadomienie Teams: {0}", ex.Message));
            }
        }

        if (options.EmailEnabled)
        {
            try
            {
                if (options.SmtpHost.Length == 0 || !options.SmtpUseTls)
                    throw new InvalidOperationException(L.T("Wymagany jest host SMTP i szyfrowanie TLS."));
                using var message = new MailMessage(new MailAddress(options.SmtpFrom), new MailAddress(options.SmtpTo))
                {
                    Subject = L.T("Bezpieczny Aktualizator — wynik cichego sprawdzania"),
                    Body = summary,
                };
                using var client = new SmtpClient(options.SmtpHost, options.SmtpPort)
                {
                    EnableSsl = true,
                    Credentials = new NetworkCredential(options.SmtpUser, options.GetSmtpPassword() ?? ""),
                    Timeout = 15000,
                };
                await client.SendMailAsync(message, ct);
            }
            catch (Exception ex) when (ex is SmtpException or ArgumentException or FormatException or InvalidOperationException or
                                           System.Security.Cryptography.CryptographicException or System.ComponentModel.Win32Exception or
                                           TaskCanceledException)
            {
                errors.Add(L.F("Powiadomienie e-mail: {0}", ex.Message));
            }
        }

        return errors;
    }

    private static bool TryTeamsWebhook(string value, out Uri uri)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out uri!) ||
            uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length > 0 || uri.Fragment.Length > 0 ||
            !(uri.Host.EndsWith(".webhook.office.com", StringComparison.OrdinalIgnoreCase) ||
              uri.Host.EndsWith(".logic.azure.com", StringComparison.OrdinalIgnoreCase)))
            return false;
        return true;
    }
}
