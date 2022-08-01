using System;
using System.Collections;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TEST2
{

    

    class Program
    {
        static private object locker = new object();
        static private Queue HeadersQEUE = new Queue();
        static private Socket mainSocket;

        static private byte[] byteData = new byte[65535];

        static int Main(string[] args)
        {


            string ip = args[0];

            string path = args[1];

            try
            {
                mainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw,
                           ProtocolType.IP);

                mainSocket.Bind(new IPEndPoint(IPAddress.Parse(ip), 0));

                mainSocket.SetSocketOption(SocketOptionLevel.IP,    //Applies only to IP packets
                                SocketOptionName.HeaderIncluded,   //Set the include header
                                                            true);//option to true

                byte[] byTrue = new byte[4] { 1, 0, 0, 0 };


                mainSocket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), null);

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message.ToString());
                Console.WriteLine("Попробуйте запустить приложение от имени администратора");
                Console.ReadLine();
                return 0;
            }


           mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(Receive), null);

           int FileWriteBuffer = 10;// Output every "n" = FileWriteBuffer headers to make it faster 
                                          //attention: increasing this parameter affects the amount of RAM required

           while (true)
           {
                if (HeadersQEUE.Count > FileWriteBuffer)
                {
                   var ss = "";
                   for (int i = 1; i < FileWriteBuffer; i++)
                   {

                       ss += HeaderToSring((IPHeader)HeadersQEUE.Dequeue());

                   }

                   File.AppendAllText(path, ss);
                }
           }
            
        }



        static void Receive(IAsyncResult ar)
        {


            _ = ListenHeadersAsync(mainSocket.EndReceive(ar), byteData);

  
            byteData = new byte[65535];
           
            mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(Receive), null);

        }

        static async Task ListenHeadersAsync(int nReceived, byte[] byteData)
        {
        
            await Task.Run(() => ListenHeaders(nReceived, byteData));

        }

        static void ListenHeaders(int nReceived, byte[] byteData)
        {
            var ipheader = new IPHeader(byteData, nReceived);


            if (ipheader.byHeaderLength > 0)
            {
                lock (locker)
                {
                    HeadersQEUE.Enqueue(ipheader);
                }

            }

        }

        private static string HeaderToSring(IPHeader Header)
        {
            
            string ss = "\n=======================================================================";


            ss += " \nIP request from " + PArseIP(Header.uiSourceIPAddress) + " to " + PArseIP(Header.uiDestinationIPAddress);


            ss += "\n\r Header length: " + Header.byHeaderLength.ToString();

            ss += "\n\r ServisesType: " + Header.byDifferentiatedServices.ToString();

            ss += "\n\r Total lenhth: " + Header.usTotalLength.ToString();

            ss += "\n\r Identificator: " + Header.usIdentification.ToString();

            ss += "\n\r Flags:" + "DF: " + Header.DF_Flag.ToString() + "     MF: " + Header.MF_Flag.ToString();
            
            ss += "\n\r Fragment Offset:" + Header.Offset.ToString();

            ss += "\n\r TTL:" + Header.byTTL.ToString();

            ss += "\n\r Protocole Type: " + ProtocoleType(Header.byProtocol);

            ss += "\n\r Header Checksum: " + Header.sIpChecksum.ToString();


            if (Header.byProtocol == 6)
            {
                ss += "\n\rIP request contains TCP with header like:";

                ss += "\n\r     Sourse Port: " + Header.usSourcePort.ToString();

                ss += "\n\r     Destination Port: " + Header.usDestinationPort.ToString();

                ss += "\n\r     Sequence Number: " + Header.uiSequenceNumber.ToString();

                ss += "\n\r     Acknowledgment Number: " + Header.uiSequenceNumber.ToString();

                ss += "\n\r     Data Offset: " + Header.usTCPHeaderLength.ToString();

                ss += "\n\r     Flags: " 
                    
                                    + "\n           NS  : " + Header.NS_Flag.ToString()
                                    + "           CWR : " + Header.CWR_Flag.ToString()
                                    + "\n           ECE : " + Header.ECE_Flag.ToString()
                                    + "           URG : " + Header.URG_Flag.ToString()
                                    + "\n           ACK : " + Header.ACK_Flag.ToString()
                                    + "           PSH : " + Header.PSH_Flag.ToString()
                                    + "\n           RST : " + Header.RST_Flag.ToString()
                                    + "           SYN : " + Header.SYN_Flag.ToString()
                                    + "\n           FIN : " + Header.FIN_Flag.ToString();

                ss += "\n\r Window size: " + Header.usWindowSize.ToString();

                ss += "\n\r Checksum: " + Header.sTCPUDPChecksum.ToString();

                ss += "\n\r Urgent Point: " + Header.usUrgentPoint.ToString();

            }
            else if(Header.byProtocol == 17)
            {
                ss += "\n\rIP request contains UDP with header like:";

                ss += "\n\r     Sourse Port: " + Header.usSourcePort.ToString();

                ss += "\n\r     Destination Port: " + Header.usDestinationPort.ToString();

                ss += "\n\r     Datagram Length: " + Header.usDatagramLength.ToString();

                ss += "\n\r     Checksum: " + Header.sTCPUDPChecksum.ToString();

            }


            return ss;
            
        }

        private static string PArseIP(uint IP) 
        {

            var ip = BitConverter.GetBytes(IP);


            string s = string.Join(".", ip);

            return s;
        }
        
        private static string ProtocoleType(byte Protocol) 
        {
            string p;

            if (Protocol == 6)
            {
                p = "TCP";
            }
            else if (Protocol == 17)
            {
                p = "UDP";
            }
            else
            {
                p = "Unknown";
            }

            return p;
        }
    }
}
