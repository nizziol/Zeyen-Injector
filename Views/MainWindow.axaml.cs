using Avalonia.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace DllInjector.ViewModels;

public partial class MainWindowViewModel : ObservableObject
{
    public ObservableCollection<string> DllList { get; } = new();
    public ObservableCollection<string> ProcessList { get; } = new();

    [ObservableProperty]
    private string? selectedDll;

    [ObservableProperty]
    private string? selectedProcess;

    public MainWindowViewModel()
    {
        RefreshProcessList();
    }

    [RelayCommand]
    private async void AddDll()
    {
        var dialog = new OpenFileDialog
        {
            AllowMultiple = false,
            Filters = new List<FileDialogFilter> {
                new FileDialogFilter { Name = "DLL", Extensions = { "dll" } }
            }
        };

        var result = await dialog.ShowAsync(new Window());

        if (result?.FirstOrDefault() is string path && File.Exists(path))
        {
            if (!DllList.Contains(path))
                DllList.Add(path);
        }
    }

    [RelayCommand]
    private void RemoveDll()
    {
        if (SelectedDll != null)
            DllList.Remove(SelectedDll);
    }

    [RelayCommand]
    private void Inject()
    {
        if (SelectedDll == null || SelectedProcess == null)
            return;

        var process = Process.GetProcessesByName(SelectedProcess).FirstOrDefault();
        if (process == null) return;

        InjectDll(process.Id, SelectedDll);
    }

    private void RefreshProcessList()
    {
        ProcessList.Clear();
        foreach (var p in Process.GetProcesses().Where(p => p.ProcessName.ToLower().Contains("gta")))
        {
            if (!ProcessList.Contains(p.ProcessName))
                ProcessList.Add(p.ProcessName);
        }
    }

    // DLL Injection (WinAPI)
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    const int PROCESS_ALL_ACCESS = 0x1F0FFF;
    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_READWRITE = 0x04;

    private void InjectDll(int pid, string dllPath)
    {
        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero) return;

        IntPtr allocMem = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)(dllPath.Length + 1), MEM_COMMIT, PAGE_READWRITE);
        byte[] bytes = Encoding.ASCII.GetBytes(dllPath);

        WriteProcessMemory(hProcess, allocMem, bytes, (uint)bytes.Length, out _);

        IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, allocMem, 0, IntPtr.Zero);
    }
}
