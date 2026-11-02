using System.Runtime.InteropServices;

namespace BezpiecznyAktualizator.Core.Scheduling;

public enum MeteredNetworkState { Unknown, Unmetered, Metered }

public static class SystemConditions
{
    [Flags]
    private enum NetworkCost : uint
    {
        Unrestricted = 0x1,
        Fixed = 0x2,
        Variable = 0x4,
        OverDataLimit = 0x10000,
        Roaming = 0x40000,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemPowerStatus
    {
        public byte AcLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public int BatteryLifeTime;
        public int BatteryFullLifeTime;
    }

    [ComImport, Guid("DCB00008-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface INetworkCostManager
    {
        [PreserveSig]
        int GetCost(out uint cost, IntPtr destinationAddress);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemPowerStatus(out SystemPowerStatus status);

    public static bool IsOnAcPower() =>
        GetSystemPowerStatus(out var status) && status.AcLineStatus == 1;

    public static MeteredNetworkState CurrentNetworkCost()
    {
        INetworkCostManager? manager = null;
        try
        {
            var type = Type.GetTypeFromCLSID(new Guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B"), throwOnError: true)!;
            manager = (INetworkCostManager)Activator.CreateInstance(type)!;
            Marshal.ThrowExceptionForHR(manager.GetCost(out var rawCost, IntPtr.Zero));
            return ClassifyNetworkCost(rawCost);
        }
        catch (Exception ex) when (ex is COMException or InvalidCastException or TypeLoadException or
                                       InvalidOperationException or UnauthorizedAccessException)
        {
            return MeteredNetworkState.Unknown;
        }
        finally
        {
            if (manager is not null && Marshal.IsComObject(manager)) Marshal.ReleaseComObject(manager);
        }
    }

    public static MeteredNetworkState ClassifyNetworkCost(uint rawCost)
    {
        var cost = (NetworkCost)rawCost;
        if ((cost & (NetworkCost.Fixed | NetworkCost.Variable | NetworkCost.OverDataLimit | NetworkCost.Roaming)) != 0)
            return MeteredNetworkState.Metered;
        return (cost & NetworkCost.Unrestricted) != 0
            ? MeteredNetworkState.Unmetered
            : MeteredNetworkState.Unknown;
    }
}
