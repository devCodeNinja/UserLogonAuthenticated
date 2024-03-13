using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserLogonAuthenticated
{
    internal class Program
    {
        private static void Main(string[] args) => Program.ExecutePocLogonTime();

        private static void ExecutePocLogonTime()
        {
            string userDomainName = Environment.UserDomainName;
            string userName = Environment.UserName;
            DateTime fdtStartTime = new DateTime();
            DateTime fdtEndTime = DateTime.Now;
            DateTime now = DateTime.Now;
            Console.WriteLine("Domain Name {0}", (object)userDomainName);
            Console.WriteLine("User Name {0}", (object)userName);
            LogonInfo.GetLogonStartEndTimeUsingEvents(userName, userDomainName, out fdtStartTime, out fdtEndTime);
            DateTime dateTime1 = fdtEndTime;
            if (now < dateTime1 || fdtStartTime == new DateTime())
            {
                Console.WriteLine("Get Start Time from backup");
                fdtStartTime = LogonInfo.GetLogonStartTime(userDomainName, userName);
            }
            List<DateTime> dateTimeList = LogonInfo.GetLogonEndTimeFromStartupProcess(fdtStartTime);
            if (0 >= dateTimeList.Count)
            {
                dateTimeList = LogonInfo.GetStartupAppsFromWMI(fdtStartTime);
                if (0 >= dateTimeList.Count)
                    fdtEndTime = LogonInfo.GetLogonEndTime("explorer");
            }
            if (0 < dateTimeList.Count)
            {
                fdtEndTime = new DateTime();
                foreach (DateTime dateTime2 in dateTimeList)
                {
                    if (dateTime2 > fdtEndTime)
                        fdtEndTime = dateTime2;
                }
            }
            if (!LogonInfo.IsDomainJoined() && !LogonInfo.IsAAdJoined())
            {
                fdtEndTime = LogonInfo.GetLogonEndTime("explorer");
                if (fdtEndTime < LogonInfo.GetLogonEndTime("widgets"))
                    fdtEndTime = LogonInfo.GetLogonEndTime("widgets");
            }
            TimeSpan timeSpan = !(fdtStartTime > fdtEndTime) ? fdtEndTime - fdtStartTime : fdtStartTime - fdtEndTime;
            Console.WriteLine("**********************************************");
            Console.WriteLine("Domain Name {0}", (object)userDomainName);
            Console.WriteLine("User Name {0}", (object)userName);
            Console.WriteLine("Logon Start Time {0}", (object)fdtStartTime);
            Console.WriteLine("Logon End Time {0}", (object)fdtEndTime);
            Console.WriteLine("Logon Duration Seconds {0}", (object)timeSpan.TotalSeconds);
            Console.WriteLine("**********************************************");
            Console.WriteLine("Press any Key to Exit");
            Console.ReadKey();
        }
    }
}
