using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Management;

namespace UserLogonAuthenticated
{
    public class LogonInfo
    {
        [DllImport("Secur32.dll")]
        private static extern uint LsaEnumerateLogonSessions(
          out ulong logonSessionCount,
          out IntPtr logonSessionList);

        [DllImport("secur32.dll")]
        private static extern uint LsaFreeReturnBuffer(IntPtr buffer);

        [DllImport("Secur32.dll")]
        private static extern uint LsaGetLogonSessionData(IntPtr luid, out IntPtr ppLogonSessionData);

        [DllImport("Kernel32.dll")]
        public static extern int WTSGetActiveConsoleSessionId();

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern void NetFreeAadJoinInformation(IntPtr pJoinInfo);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int NetGetAadJoinInformation(string pcszTenantId, out IntPtr ppJoinInfo);

        public static bool IsAAdJoined()
        {
            bool flag = false;
            IntPtr ppJoinInfo = IntPtr.Zero;
            IntPtr zero1 = IntPtr.Zero;
            IntPtr zero2 = IntPtr.Zero;
            LogonInfo.DSREG_JOIN_INFO dsregJoinInfo1 = new LogonInfo.DSREG_JOIN_INFO();
            if (LogonInfo.NetGetAadJoinInformation((string)null, out ppJoinInfo) == 0)
            {
                try
                {
                    LogonInfo.DSREG_JOIN_INFO dsregJoinInfo2 = new LogonInfo.DSREG_JOIN_INFO();
                    dsregJoinInfo1 = (LogonInfo.DSREG_JOIN_INFO)Marshal.PtrToStructure(ppJoinInfo, dsregJoinInfo2.GetType());
                    FieldInfo[] fields = typeof(LogonInfo.DSREG_JOIN_INFO).GetFields(BindingFlags.Instance | BindingFlags.Public);
                    if (fields != null)
                    {
                        foreach (FieldInfo fieldInfo in fields)
                            fieldInfo.GetValue((object)dsregJoinInfo1);
                    }
                }
                catch
                {
                }
                try
                {
                    LogonInfo.DSREG_USER_INFO structure = (LogonInfo.DSREG_USER_INFO)Marshal.PtrToStructure(dsregJoinInfo1.pUserInfo, new LogonInfo.DSREG_USER_INFO().GetType());
                    FieldInfo[] fields = typeof(LogonInfo.DSREG_USER_INFO).GetFields(BindingFlags.Instance | BindingFlags.Public);
                    if (fields != null)
                    {
                        foreach (FieldInfo fieldInfo in fields)
                            fieldInfo.GetValue((object)structure);
                    }
                }
                catch
                {
                }
                try
                {
                    object structure = Marshal.PtrToStructure(dsregJoinInfo1.pJoinCertificate, new LogonInfo.CERT_CONTEX().GetType());
                    FieldInfo[] fields = typeof(LogonInfo.CERT_CONTEX).GetFields(BindingFlags.Instance | BindingFlags.Public);
                    if (fields != null)
                    {
                        foreach (FieldInfo fieldInfo in fields)
                            fieldInfo.GetValue(structure);
                    }
                }
                catch
                {
                }
                switch (dsregJoinInfo1.joinType)
                {
                    case 0:
                    case 2:
                        flag = false;
                        break;
                    case 1:
                        flag = true;
                        break;
                }
                try
                {
                    if (ppJoinInfo != IntPtr.Zero)
                        LogonInfo.NetFreeAadJoinInformation(ppJoinInfo);
                }
                catch
                {
                }
            }
            Console.WriteLine(flag);
            return flag;
        }

        public static DateTime GetLogonStartTime(string fstrDomainName, string fstrUsername)
        {
            DateTime logonStartTime = DateTime.Now;
            DateTime dateTime1 = new DateTime(1601, 1, 1, 0, 0, 0, 0);
            IntPtr logonSessionList = IntPtr.Zero;
            ulong logonSessionCount;
            int num1 = (int)LogonInfo.LsaEnumerateLogonSessions(out logonSessionCount, out logonSessionList);
            IntPtr luid = logonSessionList;
            for (ulong index = 0; index < logonSessionCount; ++index)
            {
                IntPtr ppLogonSessionData;
                int logonSessionData = (int)LogonInfo.LsaGetLogonSessionData(luid, out ppLogonSessionData);
                LogonInfo.SECURITY_LOGON_SESSION_DATA structure = (LogonInfo.SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(ppLogonSessionData, typeof(LogonInfo.SECURITY_LOGON_SESSION_DATA));
                if (structure.PSiD != IntPtr.Zero)
                {
                    SecurityIdentifier securityIdentifier = new SecurityIdentifier(structure.PSiD);
                    string str1 = Marshal.PtrToStringUni(structure.Username.buffer).Trim();
                    string str2 = Marshal.PtrToStringUni(structure.LoginDomain.buffer).Trim();
                    Marshal.PtrToStringUni(structure.AuthenticationPackage.buffer).Trim();
                    LogonInfo.SECURITY_LOGON_TYPE logonType = (LogonInfo.SECURITY_LOGON_TYPE)structure.LogonType;
                    DateTime dateTime2 = dateTime1.AddTicks((long)structure.LoginTime);
                    if (str1.ToLower() == fstrUsername.ToLower() && str2.ToLower() == fstrDomainName.ToLower() && LogonInfo.SECURITY_LOGON_TYPE.Interactive == logonType)
                    {
                        logonStartTime = dateTime2;
                        int num2 = (int)LogonInfo.LsaFreeReturnBuffer(ppLogonSessionData);
                        break;
                    }
                }
                luid = (IntPtr)((int)luid + Marshal.SizeOf(typeof(LogonInfo.LUID)));
                int num3 = (int)LogonInfo.LsaFreeReturnBuffer(ppLogonSessionData);
            }
            int num4 = (int)LogonInfo.LsaFreeReturnBuffer(logonSessionList);
            return logonStartTime;
        }

        public static DateTime GetLogonEndTime(string fstrProcessName)
        {
            DateTime logonEndTime = DateTime.Now;
            if (string.IsNullOrEmpty(fstrProcessName))
                return logonEndTime;
            Process[] processesByName = Process.GetProcessesByName(fstrProcessName);
            if (processesByName.Length == 0)
                return logonEndTime;
            foreach (Process process in processesByName)
            {
                if (LogonInfo.WTSGetActiveConsoleSessionId() == process.SessionId && process.StartTime < logonEndTime)
                    logonEndTime = process.StartTime;
            }
            return logonEndTime;
        }

        public static void GetLogonStartEndTimeUsingEvents(
          string fstrUserName,
          string fstrDomainName,
          out DateTime fdtStartTime,
          out DateTime fdtEndTime)
        {
            DateTime dateTime1 = new DateTime();
            string str = "";
            fdtStartTime = new DateTime();
            fdtEndTime = DateTime.Now;
            try
            {
                EventLogReader eventLogReader = new EventLogReader(new EventLogQuery("System", PathType.LogName, "*[System/EventID=7001]"));
                for (EventRecord eventRecord = eventLogReader.ReadEvent(); eventRecord != null; eventRecord = eventLogReader.ReadEvent())
                {
                    DateTime dateTime2 = dateTime1;
                    DateTime? timeCreated = eventRecord.TimeCreated;
                    if ((timeCreated.HasValue ? (dateTime2 < timeCreated.GetValueOrDefault() ? 1 : 0) : 0) != 0)
                    {
                        timeCreated = eventRecord.TimeCreated;
                        dateTime1 = timeCreated.Value;
                    }
                }
            }
            catch (EventLogNotFoundException ex)
            {
                Console.WriteLine("Error while reading the event logs {0}", (object)ex.Message);
            }
            Console.WriteLine("Received last restart/shutdown success {0}", (object)dateTime1);
            try
            {
                EventLogReader eventLogReader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, "*[System/EventID=4634]"));
                for (EventRecord eventRecord = eventLogReader.ReadEvent(); eventRecord != null; eventRecord = eventLogReader.ReadEvent())
                {
                    DateTime dateTime3 = dateTime1;
                    DateTime? timeCreated = eventRecord.TimeCreated;
                    if ((timeCreated.HasValue ? (dateTime3 <= timeCreated.GetValueOrDefault() ? 1 : 0) : 0) != 0 && 2 < eventRecord.Properties.Count && eventRecord.Properties[1].Value.ToString().ToLower().Equals(fstrUserName.ToLower()) && eventRecord.Properties[2].Value.ToString().ToLower().Equals(fstrDomainName.ToLower()))
                    {
                        DateTime dateTime4 = fdtEndTime;
                        timeCreated = eventRecord.TimeCreated;
                        if ((timeCreated.HasValue ? (dateTime4 > timeCreated.GetValueOrDefault() ? 1 : 0) : 0) != 0 && !string.IsNullOrEmpty(eventRecord.Properties[0].Value.ToString()))
                        {
                            str = eventRecord.Properties[0].Value.ToString();
                            ref DateTime local = ref fdtEndTime;
                            timeCreated = eventRecord.TimeCreated;
                            DateTime dateTime5 = timeCreated.Value;
                            local = dateTime5;
                        }
                    }
                }
            }
            catch (EventLogNotFoundException ex)
            {
                Console.WriteLine("Error while reading the event logs {0}", (object)ex.Message);
            }
            if (string.IsNullOrEmpty(str))
                fdtEndTime = fdtStartTime = dateTime1;
            Console.WriteLine("Received last Log off based on restart success Sessio Id : {0}", (object)str);
            try
            {
                EventLogReader eventLogReader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, "*[System/EventID=4624]"));
                for (EventRecord eventRecord = eventLogReader.ReadEvent(); eventRecord != null; eventRecord = eventLogReader.ReadEvent())
                {
                    DateTime dateTime6 = dateTime1;
                    DateTime? timeCreated = eventRecord.TimeCreated;
                    if ((timeCreated.HasValue ? (dateTime6 <= timeCreated.GetValueOrDefault() ? 1 : 0) : 0) != 0 && 6 < eventRecord.Properties.Count && eventRecord.Properties[4].Value.ToString().ToLower().Equals(str.ToLower()))
                    {
                        DateTime dateTime7 = fdtEndTime;
                        timeCreated = eventRecord.TimeCreated;
                        if ((timeCreated.HasValue ? (dateTime7 >= timeCreated.GetValueOrDefault() ? 1 : 0) : 0) != 0)
                        {
                            ref DateTime local = ref fdtStartTime;
                            timeCreated = eventRecord.TimeCreated;
                            DateTime dateTime8 = timeCreated.Value;
                            local = dateTime8;
                        }
                    }
                }
            }
            catch (EventLogNotFoundException ex)
            {
                Console.WriteLine("Error while reading the event logs {0}", (object)ex.Message);
            }
            Console.WriteLine("Start {0}, End {1}, Filter {2}", (object)fdtStartTime, (object)fdtEndTime, (object)dateTime1);
            if (2.0 <= (fdtStartTime - dateTime1).TotalSeconds || 2.0 <= (fdtEndTime - dateTime1).TotalSeconds)
                fdtStartTime = fdtEndTime = dateTime1;
            Console.WriteLine("Received last Log on based on restart success {0}", (object)fdtStartTime);
        }

        private static List<DateTime> GetLogonEndTimeFromRegistry(
          DateTime fdtStartTime,
          string fstrRegistryName,
          bool fbLocalMachine,
          bool fbWow64)
        {
            DateTime now = DateTime.Now;
            List<DateTime> timeFromRegistry = new List<DateTime>();
            RegistryKey registryKey1 = !fbWow64 ? RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32) : RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            RegistryKey registryKey2 = !fbLocalMachine ? registryKey1.OpenSubKey(fstrRegistryName, false) : registryKey1.OpenSubKey(fstrRegistryName, false);
            foreach (string valueName in registryKey2.GetValueNames())
            {
                string str = (string)registryKey2.GetValue(valueName);
                if (str.Contains(".exe"))
                {
                    DateTime logonEndTime = LogonInfo.GetLogonEndTime(str.Substring(str.LastIndexOf("\\") + 1, str.IndexOf(".exe") - str.LastIndexOf("\\") - 1));
                    Console.WriteLine("Process Name {0}", (object)logonEndTime);
                    if (fdtStartTime < logonEndTime && now > logonEndTime && 1.0 > (logonEndTime - fdtStartTime).TotalMinutes)
                        timeFromRegistry.Add(logonEndTime);
                }
            }
            return timeFromRegistry;
        }

        public static List<DateTime> GetLogonEndTimeFromStartupProcess(DateTime fdtStartTime)
        {
            DateTime now = DateTime.Now;
            bool flag = false;
            List<DateTime> timeFromRegistry = LogonInfo.GetLogonEndTimeFromRegistry(fdtStartTime, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true, true);
            if (0 < timeFromRegistry.Count)
                flag = true;
            if (!flag)
            {
                timeFromRegistry = LogonInfo.GetLogonEndTimeFromRegistry(fdtStartTime, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true, false);
                if (0 < timeFromRegistry.Count)
                    flag = true;
                if (!flag)
                {
                    timeFromRegistry = LogonInfo.GetLogonEndTimeFromRegistry(fdtStartTime, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", false, true);
                    if (0 < timeFromRegistry.Count)
                        flag = true;
                    if (!flag)
                        timeFromRegistry = LogonInfo.GetLogonEndTimeFromRegistry(fdtStartTime, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", false, false);
                }
            }
            return timeFromRegistry;
        }

        public static List<DateTime> GetStartupAppsFromWMI(DateTime fdtStartTime)
        {
            DateTime now = DateTime.Now;
            List<DateTime> startupAppsFromWmi = new List<DateTime>();
            foreach (ManagementObject instance in new ManagementClass("Win32_StartupCommand").GetInstances())
            {
                DateTime logonEndTime = LogonInfo.GetLogonEndTime(instance["Caption"].ToString());
                string str = instance["Command"].ToString();
                if (now < logonEndTime && 0 < str.IndexOf(".exe"))
                    logonEndTime = LogonInfo.GetLogonEndTime(str.Substring(str.LastIndexOf("\\") + 1, str.IndexOf(".exe") - str.LastIndexOf("\\") - 1));
                if (fdtStartTime < logonEndTime && now > logonEndTime && 1.0 > (logonEndTime - fdtStartTime).TotalMinutes)
                    startupAppsFromWmi.Add(logonEndTime);
            }
            return startupAppsFromWmi;
        }

        public static bool IsDomainJoined()
        {
            ManagementObject managementObject = new ManagementObject(string.Format("Win32_ComputerSystem.Name='{0}'", (object)Environment.MachineName));
            Console.WriteLine(managementObject["PartOfDomain"]);
            return (bool)managementObject["PartOfDomain"];
        }

        private struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;
        }

        private struct LUID
        {
            public uint LowPart;
            public uint HighPart;
        }

        private struct SECURITY_LOGON_SESSION_DATA
        {
            public uint Size;
            public LogonInfo.LUID LoginID;
            public LogonInfo.LSA_UNICODE_STRING Username;
            public LogonInfo.LSA_UNICODE_STRING LoginDomain;
            public LogonInfo.LSA_UNICODE_STRING AuthenticationPackage;
            public uint LogonType;
            public uint Session;
            public IntPtr PSiD;
            public ulong LoginTime;
            public LogonInfo.LSA_UNICODE_STRING LogonServer;
            public LogonInfo.LSA_UNICODE_STRING DnsDomainName;
            public LogonInfo.LSA_UNICODE_STRING Upn;
        }

        private enum SECURITY_LOGON_TYPE : uint
        {
            Interactive = 2,
            Network = 3,
            Batch = 4,
            Service = 5,
            Proxy = 6,
            Unlock = 7,
            NetworkCleartext = 8,
            NewCredentials = 9,
            RemoteInteractive = 10, // 0x0000000A
            CachedInteractive = 11, // 0x0000000B
            CachedRemoteInteractive = 12, // 0x0000000C
            CachedUnlock = 13, // 0x0000000D
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DSREG_USER_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string UserEmail;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string UserKeyId;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string UserKeyName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CERT_CONTEX
        {
            public uint dwCertEncodingType;
            public byte pbCertEncoded;
            public uint cbCertEncoded;
            public IntPtr pCertInfo;
            public IntPtr hCertStore;
        }

        public enum DSREG_JOIN_TYPE
        {
            DSREG_UNKNOWN_JOIN,
            DSREG_DEVICE_JOIN,
            DSREG_WORKPLACE_JOIN,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DSREG_JOIN_INFO
        {
            public int joinType;
            public IntPtr pJoinCertificate;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string DeviceId;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string IdpDomain;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string TenantId;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string JoinUserEmail;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string TenantDisplayName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string MdmEnrollmentUrl;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string MdmTermsOfUseUrl;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string MdmComplianceUrl;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string UserSettingSyncUrl;
            public IntPtr pUserInfo;
        }
    }
}
