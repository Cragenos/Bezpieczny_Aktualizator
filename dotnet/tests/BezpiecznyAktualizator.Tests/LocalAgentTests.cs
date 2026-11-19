using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using BezpiecznyAktualizator.Core.Agent;
using BezpiecznyAktualizator.Core.Logging;
using BezpiecznyAktualizator.Core.Models;
using BezpiecznyAktualizator.Core.Scheduling;
using BezpiecznyAktualizator.Services;

namespace BezpiecznyAktualizator.Tests;

[Collection(nameof(SyslogTests))]
public class LocalAgentTests
{
    private static readonly LocalAgentCandidate[] Candidates =
    [
        new("7zip.7zip", "7-Zip", "Igor Pavlov", "26.05", "26.06", "winget", "A", ""),
        new("Mozilla.Firefox", "Firefox", "Mozilla", "140.0", "141.0b1", "winget", "A", ""),
    ];

    [Theory]
    [InlineData("http://127.0.0.1:11434/v1", "http://127.0.0.1:11434/v1/")]
    [InlineData("http://localhost:1234/v1/", "http://localhost:1234/v1/")]
    [InlineData("https://[::1]:8080", "https://[::1]:8080/")]
    [InlineData("http://127.5.6.7:8080/api/v1", "http://127.5.6.7:8080/api/v1/")]
    public void LoopbackEndpointsAreAccepted(string value, string expected)
    {
        Assert.True(LocalAgentOptions.TryGetEndpoint(value, out var endpoint));
        Assert.Equal(expected, endpoint.AbsoluteUri);
    }

    [Theory]
    [InlineData("http://192.168.1.10:11434/v1")]
    [InlineData("https://api.openai.com/v1")]
    [InlineData("http://localhost.example.com/v1")]
    [InlineData("http://127.0.0.1.nip.io/v1")]
    [InlineData("ftp://127.0.0.1/v1")]
    [InlineData("http://user:pass@127.0.0.1/v1")]
    [InlineData("http://127.0.0.1/v1?x=1")]
    [InlineData("http://127.0.0.1/v1#x")]
    [InlineData("127.0.0.1:11434")]
    [InlineData("")]
    public void NonLoopbackOrUnsafeEndpointsAreRejected(string value) =>
        Assert.False(LocalAgentOptions.TryGetEndpoint(value, out _));

    [Fact]
    public void ReviewApprovesOnlyLiteralTrueForKnownPackages()
    {
        var review = LocalAgentClient.ParseReview("""
            ```json
            {"decisions":[
              {"id":"7zip.7zip","install":true,"reason":"stable\u0007 security fix"},
              {"id":"Mozilla.Firefox","install":"true","reason":"beta"},
              {"id":"Evil.Package","install":true,"reason":"injected"}
            ]}
            ```
            """, Candidates);

        Assert.True(review.Approves("7ZIP.7zip"));
        Assert.Equal("stable  security fix", review.ReasonFor("7zip.7zip"));
        Assert.False(review.Approves("Mozilla.Firefox"));
        Assert.False(review.Approves("Evil.Package"));
        Assert.DoesNotContain(review.Decisions, d => d.Id == "Evil.Package");
    }

    [Fact]
    public void ConflictingOrMissingDecisionsAreRejected()
    {
        var review = LocalAgentClient.ParseReview(
            """{"decisions":[{"id":"7zip.7zip","install":true},{"id":"7zip.7zip","install":false}]}""", Candidates);

        Assert.False(review.Approves("7zip.7zip"));
        Assert.False(review.Approves("Mozilla.Firefox"));
        Assert.NotEmpty(review.ReasonFor("Mozilla.Firefox"));
    }

    [Theory]
    [InlineData("Nie wiem.")]
    [InlineData("{\"decisions\": 5}")]
    [InlineData("[{\"id\":\"7zip.7zip\"}]")]
    [InlineData("{not json}")]
    public void MalformedAnswersThrow(string content) =>
        Assert.Throws<LocalAgentException>(() => LocalAgentClient.ParseReview(content, Candidates));

    [Fact]
    public async Task ReviewPostsToLocalChatCompletionsWithoutStreaming()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, """
            {"choices":[{"message":{"content":"{\"decisions\":[{\"id\":\"7zip.7zip\",\"install\":true,\"reason\":\"ok\"}]}"}}]}
            """);
        using var http = LocalAgentClient.CreateHttpClient(handler);
        var options = new LocalAgentOptions { Endpoint = "http://127.0.0.1:11434/v1", Model = "llama3.2", Instructions = "No browsers" };

        var review = await LocalAgentClient.ReviewAsync(options, Candidates, http);

        Assert.True(review.Approves("7zip.7zip"));
        Assert.False(review.Approves("Mozilla.Firefox"));
        Assert.Equal(HttpMethod.Post, handler.Method);
        Assert.Equal("http://127.0.0.1:11434/v1/chat/completions", handler.Uri?.AbsoluteUri);
        var body = JsonNode.Parse(handler.Body!)!;
        Assert.Equal("llama3.2", (string?)body["model"]);
        Assert.False((bool?)body["stream"]);
        Assert.Contains("No browsers", (string?)body["messages"]![1]!["content"]);
        Assert.Contains("\"id\":\"Mozilla.Firefox\"", (string?)body["messages"]![1]!["content"]);
        Assert.Contains("\"availableVersion\":\"141.0b1\"", (string?)body["messages"]![1]!["content"]);
        Assert.Equal("system", (string?)body["messages"]![0]!["role"]);
    }

    [Fact]
    public async Task ReviewRequiresModelAndHttpSuccess()
    {
        using var http = LocalAgentClient.CreateHttpClient(new FakeHandler(HttpStatusCode.InternalServerError, "{}"));
        await Assert.ThrowsAsync<LocalAgentException>(() =>
            LocalAgentClient.ReviewAsync(new LocalAgentOptions { Model = "" }, Candidates, http));
        await Assert.ThrowsAsync<LocalAgentException>(() =>
            LocalAgentClient.ReviewAsync(new LocalAgentOptions { Model = "m" }, Candidates, http));
        await Assert.ThrowsAsync<LocalAgentException>(() =>
            LocalAgentClient.ReviewAsync(new LocalAgentOptions { Model = "m", Endpoint = "http://10.0.0.5:11434/v1" }, Candidates, http));
    }

    [Fact]
    public async Task ListModelsReadsOpenAiModelList()
    {
        var handler = new FakeHandler(HttpStatusCode.OK, """{"data":[{"id":"llama3.2"},{"id":"qwen2.5"},{"id":"llama3.2"},{"id":5}]}""");
        using var http = LocalAgentClient.CreateHttpClient(handler);

        var models = await LocalAgentClient.ListModelsAsync(new LocalAgentOptions { Endpoint = "http://localhost:1234/v1/" }, http);

        Assert.Equal(["llama3.2", "qwen2.5"], models);
        Assert.Equal("http://localhost:1234/v1/models", handler.Uri?.AbsoluteUri);
    }

    [Fact]
    public async Task ScheduledGateKeepsOnlyApprovedUpdates()
    {
        var logEnabled = Syslog.Enabled;
        Syslog.Enabled = false;
        try
        {
            var zip = new Software { Name = "7-Zip", Version = "26.05", AvailableVersion = "26.06", WingetId = "7zip.7zip" };
            var firefox = new Software { Name = "Firefox", Version = "140.0", AvailableVersion = "141.0b1", WingetId = "Mozilla.Firefox" };
            var state = new ScheduleState();
            var review = LocalAgentClient.ParseReview(
                """{"decisions":[{"id":"7zip.7zip","install":true},{"id":"Mozilla.Firefox","install":false,"reason":"beta"}]}""", Candidates);

            var approved = await ScheduledRunner.ApplyAgentReviewAsync(new LocalAgentOptions { Model = "m" }, [zip, firefox], state,
                (_, _) => Task.FromResult(review));

            Assert.Equal([zip], approved);
            Assert.Equal(["Firefox 140.0 → 141.0b1"], state.Skipped);
        }
        finally
        {
            Syslog.Enabled = logEnabled;
        }
    }

    [Fact]
    public async Task ScheduledGateFailsClosedWhenAgentIsUnavailable()
    {
        var logEnabled = Syslog.Enabled;
        Syslog.Enabled = false;
        try
        {
            var zip = new Software { Name = "7-Zip", Version = "26.05", AvailableVersion = "26.06", WingetId = "7zip.7zip" };
            var state = new ScheduleState();

            var approved = await ScheduledRunner.ApplyAgentReviewAsync(new LocalAgentOptions { Model = "m" }, [zip], state,
                (_, _) => throw new LocalAgentException("offline"));

            Assert.Empty(approved);
            Assert.Equal(["7-Zip 26.05 → 26.06"], state.Skipped);
            Assert.Contains("offline", state.SkipReason);
        }
        finally
        {
            Syslog.Enabled = logEnabled;
        }
    }

    private sealed class FakeHandler(HttpStatusCode status, string response) : HttpMessageHandler
    {
        public HttpMethod? Method { get; private set; }
        public Uri? Uri { get; private set; }
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Method = request.Method;
            Uri = request.RequestUri;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
            return new HttpResponseMessage(status) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }
}
