using Microsoft.Extensions.Hosting.WindowsServices;
using Watchtower.Core.Config;
using Watchtower.Core.Ipc;
using Watchtower.Core.Updates;
using Watchtower.Service.Actions;
using Watchtower.Service.Engine;
using Watchtower.Service.Hosting;
using Watchtower.Service.Ipc;
using Watchtower.Service.Native;
using Watchtower.Service.Sources;
using Watchtower.Service.Updates;

var cli = CommandLine.Parse(args);
var paths = ServicePaths.Create(cli.DataDir);
CrashReporting.InstallLocalHandlers(paths);

// The update gate runs before anything else, so even a build that crashes during
// startup gets rolled back: Windows restarts the service, and each start counts.
var gate = new UpdateHealthGate(paths.UpdateStateFile);
var gateResult = gate.OnServiceStart(AppVersion.Current, DateTimeOffset.UtcNow);
if (gateResult.Action == GateAction.Rollback && gateResult.Package is not null && !cli.Console)
{
    UpdateService.LaunchInstaller(gateResult.Package, paths, log: null);
    return 0;
}

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});
builder.Services.AddWindowsService(o => o.ServiceName = "Watchtower");
if (WindowsServiceHelpers.IsWindowsService())
{
    builder.Services.AddSingleton<IHostLifetime, WatchtowerLifetime>();
}
builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(20));
builder.Services.Configure<WatchtowerOptions>(builder.Configuration.GetSection(WatchtowerOptions.Section));

builder.Services.AddSingleton(paths);
builder.Services.AddSingleton(new StartupGate(gate, gateResult));
builder.Services.AddSingleton<EngineContext>();
builder.Services.AddSingleton<HeartbeatFile>();
builder.Services.AddSingleton<ProcessInfo>();
builder.Services.AddSingleton<SignatureVerifier>();
builder.Services.AddSingleton<Remediator>();
builder.Services.AddSingleton<ExposureCollector>();
builder.Services.AddSingleton(sp => new DebloatEngine(new JsonFileStore<DebloatState>(sp.GetRequiredService<ServicePaths>().DebloatFile)));
builder.Services.AddSingleton<RpcDispatcher>();
builder.Services.AddSingleton<Api>();

builder.Services.AddSingleton<PipeServer>();
builder.Services.AddSingleton<IEventSink>(sp => sp.GetRequiredService<PipeServer>());
builder.Services.AddSingleton<WatchtowerEngine>();
builder.Services.AddSingleton<OffsiteService>();
builder.Services.AddSingleton<UpdateService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<PipeServer>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<WatchtowerEngine>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<OffsiteService>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<UpdateService>());
if (cli.SmokeSeconds > 0)
{
    builder.Services.AddSingleton(new SmokeTestOptions(cli.SmokeSeconds));
    builder.Services.AddHostedService<SmokeTest>();
}

var host = builder.Build();

// Wire alerts to the UI and the backup trigger, and register the API, before anything starts.
var ctx = host.Services.GetRequiredService<EngineContext>();
var events = host.Services.GetRequiredService<IEventSink>();
var offsite = host.Services.GetRequiredService<OffsiteService>();
ctx.Pipeline.Published += alert =>
{
    events.Broadcast("alert", alert);
    offsite.OnAlert(alert);
};
host.Services.GetRequiredService<Api>();
var rpcLog = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Watchtower.Rpc");
host.Services.GetRequiredService<RpcDispatcher>().Failed += (method, caller, ex) =>
    rpcLog.LogError(ex, "Request {Method} from {User} (admin: {Admin}) failed", method, caller.UserName, caller.IsAdministrator);

var options = host.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<WatchtowerOptions>>().Value;
CrashReporting.Configure(options.SentryDsn, ctx.Settings.Value.CrashReports);

await host.RunAsync();
return Environment.ExitCode;
