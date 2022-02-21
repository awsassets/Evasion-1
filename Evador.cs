using System.IO;
using System.Management;
using System.Windows.Forms;
using System.Management.Automation;

namespace Evasion1
{
    class Evador
    {
        private const int MIN_RAM_AMOUNT = 4;
        private const int MIN_SIZE_AMOUNT = 100;
        private const int MIN_PROCESS_CORES_AMOUNT = 2;
        
        private readonly string[] KNOWN_SERVICES = { "VMTools", "Vmhgfs", "VMMEMCTL", "Vmmouse", "Vmrawdsk", "Vmusbmouse", "Vmvss", "Vmscsi", "Vmxnet", "vmx_svga", "Vmware Tools", "Vmware Physical Disk Helper Service" };
        private readonly string[] KNOWN_PROCESSES = { "vmtoolsd.exe", "vmwaretrat.exe", "vmwareuser.exe", "vmacthlp.exe", "vboxservice.exe", "vboxtray.exe", "vbox.exe", "wireshark.exe", "fiddler.exe", "procmon64.exe", "procmon.exe", "procexp.exe", "procexp64.exe", "sysmon64.exe", "sysmon.exe", "processhacker.exe", "ollydbg.exe", "immunitydebugger.exe", "x64dbg.exe", "x32dbg.exe", "windbgx64.exe", "windbgx86.exe" };
        private readonly string[] KNOWN_FILES = { "C:\\Windows\\System32\\Drivers\\Vmmouse.sys", "C:\\Windows\\System32\\Drivers\\vm3dgl.dll", "C:\\Windows\\System32\\Drivers\\vmdum.dll", "C:\\Windows\\System32\\Drivers\\vm3dver.dll", "C:\\Windows\\System32\\Drivers\\vmtray.dll", "C:\\Windows\\System32\\Drivers\\VMToolsHook.dll", "C:\\Windows\\System32\\Drivers\\vmmousever.dll", "C:\\Windows\\System32\\Drivers\\vmhgfs.dll", "C:\\Windows\\System32\\Drivers\\vmGuestLib.dll", "C:\\Windows\\System32\\Drivers\\VmGuestLibJava.dll", "C:\\Windows\\System32\\Driversvmhgfs.dll", "C:\\Windows\\System32\\Drivers\\VBoxMouse.sys", "C:\\Windows\\System32\\Drivers\\VBoxGuest.sys", "C:\\Windows\\System32\\Drivers\\VBoxSF.sys", "C:\\Windows\\System32\\Drivers\\VBoxVideo.sys", "C:\\Windows\\System32\\vboxdisp.dll", "C:\\Windows\\System32\\vboxhook.dll", "C:\\Windows\\System32\\vboxmrxnp.dll", "C:\\Windows\\System32\\vboxogl.dll", "C:\\Windows\\System32\\vboxoglarrayspu.dll", "C:\\Windows\\System32\\vboxoglcrutil.dll", "C:\\Windows\\System32\\vboxoglerrorspu.dll", "C:\\Windows\\System32\\vboxoglfeedbackspu.dll", "C:\\Windows\\System32\\vboxoglpackspu.dll", "C:\\Windows\\System32\\vboxoglpassthroughspu.dll", "C:\\Windows\\System32\\vboxservice.exe", "C:\\Windows\\System32\\vboxtray.exe", "C:\\Windows\\System32\\VBoxControl.exe" };

        private List<string>? runningProcesses = new();

        public Evador() { }
        
        public async Task<bool> EvadeDetection()
        {
            runningProcesses = await ExecutePowershell("tasklist");
            
            if (IsDebuggerPresent())
                return false;
            else if (HardwareTests())
                return false;
            else if (await IsRunningOnVM())
                return false;

            return true;
        }
        
        private async Task<bool> IsRunningOnVM()
        {
            List<string>? serviceOutput = await ExecutePowershell("get-service", null, "Name");
            if (serviceOutput != null)
            {
                foreach (string service in KNOWN_SERVICES)
                {
                    foreach (string s in serviceOutput)
                    {
                        if (string.Compare(s.ToLower(), service.ToLower()) == 0)
                            return true;
                    }
                }
            }

            foreach (string path in KNOWN_FILES)
            {
                if (File.Exists(path))
                    return true;
            }

            if (runningProcesses != null)
            {
                foreach (string process in KNOWN_PROCESSES)
                {
                    if (runningProcesses.Contains(process))
                        return true;
                }
            }

            if (Screen.AllScreens.Length == 1)
            {
                Rectangle screen = Screen.PrimaryScreen.Bounds;
                int width = screen.Width, height = screen.Height;
                if ((width == 800 && height == 600) || (width == 1024 && height == 768))
                    return true;
            }

            return false;
        }

        private static bool IsDebuggerPresent()
        {
            return System.Diagnostics.Debugger.IsAttached;
        }

        private static bool HardwareTests()
        {
            try
            {
                double totalSize = 0;
                double ramAmount = 0;

                List<string>? fansData = new();
                ManagementObjectCollection? collection = GetWmiQuery("SELECT * FROM WIN32_FAN");
                if (collection != null)
                {
                    foreach (ManagementObject managementObject in collection)
                    {
                        fansData.Add(managementObject.ToString());
                    }
                }
                
                DriveInfo[] drives = DriveInfo.GetDrives();
                foreach (DriveInfo drive in drives)
                {
                    if (drive.IsReady)
                        totalSize += drive.TotalSize;
                }

                ManagementObjectCollection? results = GetWmiQuery("SELECT * FROM Win32_OperatingSystem");
                if (results != null)
                {
                    foreach (ManagementObject result in results)
                    {
                        double bytes = Convert.ToDouble(result["TotalVisibleMemorySize"]);
                        ramAmount = Math.Round(bytes / (1024 * 1024), 2);
                    }
                }

                if (Environment.ProcessorCount <= MIN_PROCESS_CORES_AMOUNT)
                    return true;
                else if (totalSize <= MIN_SIZE_AMOUNT)
                    return true;
                else if (ramAmount <= MIN_RAM_AMOUNT)
                    return true;
                else if (fansData == null || fansData.Count == 0)
                    return true;
                
                foreach (string fData in fansData)
                {
                    if (fData.Contains("ObjectNotFound"))
                        return true;
                }

                return false;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
        }

        private static async Task<List<string>> ExecutePowershell(string command, Dictionary<object, object>? parameters = null, string member = "")
        {
            List<string> total = new();
            using (PowerShell powershell = PowerShell.Create())
            {
                powershell.AddCommand(command);
                if (parameters != null)
                    powershell.AddParameters(parameters);

                ICollection<PSObject> result = await powershell.InvokeAsync();
                foreach (PSObject psObject in result)
                {
                    if (member == "")
                    {
                        string ps = psObject.ToString();
                        if (StringValid(ps))
                            total.Add(ps);
                    }
                    else
                    {
                        PSMemberInfo? psMember = psObject.Members[member];
                        if (psMember != null)
                        {
                            string? memberValue = psMember.Value.ToString();
                            if (StringValid(memberValue))
                                total.Add(memberValue);
                        }
                    }
                }
            }

            return total;
        }

        private static ManagementObjectCollection? GetWmiQuery(string? query)
        {
            if (string.IsNullOrEmpty(query))
                return null;

            ObjectQuery wql = new(query);
            ManagementObjectSearcher searcher = new(wql);

            return searcher.Get();
        }

        private static bool StringValid(string str) => !string.IsNullOrEmpty(str) && !string.IsNullOrWhiteSpace(str);
    }
}
