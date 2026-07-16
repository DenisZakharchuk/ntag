using System.Reflection;
using BenchmarkDotNet.Running;

// BenchmarkSwitcher (rather than BenchmarkRunner.Run<T>) so additional benchmark classes
// can be added later without changing this file - `dotnet run -c Release` will prompt to
// pick one (or pass a filter, e.g. `--filter *CmacVerification*`).
BenchmarkSwitcher.FromAssembly(Assembly.GetExecutingAssembly()).Run(args);
