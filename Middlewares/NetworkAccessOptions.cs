namespace HanaMedia.Middlewares;

public class NetworkAccessOptions
{
    public string[] AllowedCidrs { get; set; } = Array.Empty<string>();
}
