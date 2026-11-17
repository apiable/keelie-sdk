using System.Runtime.CompilerServices;

namespace Keelie.Tests;

/// <summary>One codebase serves both adapters: the same token check, through both.</summary>
public sealed class StructureTests
{
    private static string Source([CallerFilePath] string path = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "..", "..", "src"));

    // The files that may verify a token: the verifier and its key set in the core, and the one
    // guard of the adapters.
    private static readonly HashSet<string> Core = ["TokenVerifier.cs", "SigningKeys.cs"];

    [Fact]
    public void No_file_outside_the_core_holds_its_own_token_check()
    {
        var files = Directory.GetFiles(Source(), "*.cs", SearchOption.AllDirectories)
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .ToList();
        Assert.NotEmpty(files);
        foreach (var file in files)
        {
            var name = Path.GetFileName(file);
            var text = File.ReadAllText(file);
            if (!Core.Contains(name))
            {
                Assert.False(text.Contains("RSA", StringComparison.Ordinal), $"{name} uses RSA");
                Assert.False(text.Contains("VerifyData", StringComparison.Ordinal), $"{name} verifies a signature");
                Assert.False(text.Contains("GetKeyAsync", StringComparison.Ordinal), $"{name} reads the key set");
            }
            if (name != "TokenVerifier.cs" && name != "Guard.cs")
            {
                Assert.False(text.Contains(".VerifyAsync(", StringComparison.Ordinal), $"{name} calls VerifyAsync itself");
            }
        }
    }

    [Fact]
    public void Both_adapters_go_through_the_one_guard()
    {
        var adapter = Path.Combine(Source(), "Keelie.AspNetCore");
        Assert.Contains("new Guard(verifier, metadata)", File.ReadAllText(Path.Combine(adapter, "KeelieApplicationBuilderExtensions.cs")), StringComparison.Ordinal);
        Assert.Contains("_guard.InvokeAsync", File.ReadAllText(Path.Combine(adapter, "McpGuard.cs")), StringComparison.Ordinal);
    }
}
