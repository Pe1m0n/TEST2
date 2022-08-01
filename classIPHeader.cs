using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace TEST2
{

    class IPHeader
    {
        //TODO Возвращаемые свойства
        #region IP Header fields 
        private byte byVersionAndHeaderLength; // Eight bits for version and header 
                                               // length 
        public byte byDifferentiatedServices { get; } // Eight bits for differentiated 
                                                      // services
        public ushort usTotalLength { get; }          // Sixteen bits for total length 

        public ushort usIdentification { get; }        // Sixteen bits for identification

        private ushort usFlagsAndOffset;        // Eight bits for flags and frag. 
                                                // offset 
        public byte byTTL { get; }                    // Eight bits for TTL (Time To Live) 

        public byte byProtocol;// Eight bits for the underlying protocol 

        public short sIpChecksum { get; }                // Sixteen bits for checksum of the 
                                                       //  header 
        public uint uiSourceIPAddress { get; }        // Thirty two bit source IP Address 

        public uint uiDestinationIPAddress { get; }   // Thirty two bit destination IP Address 
         
        public byte byHeaderLength { get; }             //Header length 

        public bool DF_Flag { get; } //DontFagment Flag

        public bool MF_Flag { get; } //MoreFagment Flag

        public ushort Offset { get; } //Fragment Offset in bytes

        #endregion
        private byte[] byIPData = new byte[65535]; //Data carried by the IP

        #region TCP/UDP Header fields
        public ushort usSourcePort { get; } //Sixteen bits for UDP/TCP Source Port

        public ushort usDestinationPort { get; } //Sixteen bits for UDP/TCP Destination Port

        public uint uiSequenceNumber { get; } //Thirty two bit for TCP Sequence number

        public uint uiAcknowledgmentNumber { get; } //Thirty two bit for TCP Acknowledgment Number


        private ushort usDataOffsetAndFlags; //Sixteen bits for TCP: 4 bits  Data Offset , 3 Reserved bits, 9 bit Flags

        public ushort usTCPHeaderLength { get; }

        public bool NS_Flag { get; } //ECN-nonce
        public bool CWR_Flag { get; } //Congestion Window Reduced
        public bool ECE_Flag { get; }//ECN-Echo
        public bool URG_Flag { get; }//Urgent pointer field is significant
        public bool ACK_Flag { get; }//Acknowledgement field is significant
        public bool PSH_Flag { get; }//Push function
        public bool RST_Flag { get; }//Reset the connection
        public bool SYN_Flag { get; }//Synchronize sequence numbers
        public bool FIN_Flag { get; }//FIN bit used for connection termination


        public ushort usWindowSize { get; }//Sixteen bits for TCP Window Size

        public short sTCPUDPChecksum { get; }//Sixteen bits for TCP/UDP Checksum

        public ushort usUrgentPoint { get; }//Sixteen bits for TCP Checksum Urgent Point

        public ushort usDatagramLength { get; }//Sixteen bits for UDP Datagram Length


        #endregion


        public IPHeader(byte[] byBuffer, int nReceived)
        {
            try
            {

                #region Reading IP Header
                //Create MemoryStream out of the received bytes
                MemoryStream memoryStream = new MemoryStream(byBuffer, 0, nReceived);

                //Next we create a BinaryReader out of the MemoryStream
                BinaryReader binaryReader = new BinaryReader(memoryStream);

                //The first eight bits of the IP header contain the version and
                //header length so we read them
                byVersionAndHeaderLength = binaryReader.ReadByte();

                //The next eight bits contain the Differentiated services
                byDifferentiatedServices = binaryReader.ReadByte();

                //Next eight bits hold the total length of the datagram
                usTotalLength =
                         (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                //Next sixteen have the identification bytes
                usIdentification =
                          (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                //Next sixteen bits contain the flags and fragmentation offset
                usFlagsAndOffset =
                          (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                //Next eight bits have the TTL value
                byTTL = binaryReader.ReadByte();

                //Next eight represent the protocol encapsulated in the datagram
                byProtocol = binaryReader.ReadByte();

                //Next sixteen bits contain the checksum of the header
                sIpChecksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                //Next thirty two bits have the source IP address
                uiSourceIPAddress = (uint)(binaryReader.ReadInt32());

                //Next thirty two hold the destination IP address
                uiDestinationIPAddress = (uint)(binaryReader.ReadInt32());

                //Now we calculate the header length
                byHeaderLength = byVersionAndHeaderLength;


                byHeaderLength = ExtractIPHeaderlength(byVersionAndHeaderLength);

                DF_Flag = GetBit(usFlagsAndOffset, 14);
                MF_Flag = GetBit(usFlagsAndOffset, 13);

                Offset = GetFromBits(usFlagsAndOffset, 4);



                #endregion

                

                #region Reading UDP and TCP Header
                if (usTotalLength - byHeaderLength >= 0)//Ignore packets with a 0 Total length (sent to IANA)
                {
                    //Copy the data carried by the datagram into another array so that
                    //according to the protocol being carried in the IP datagram
                    Array.Copy(byBuffer,
                               byHeaderLength, //start copying from the end of the header
                               byIPData, 0, usTotalLength - byHeaderLength);

                    //Create MemoryStream out of the received bytes
                    memoryStream = new MemoryStream(byIPData, 0, nReceived);

                    //Next we create a BinaryReader out of the MemoryStream
                    binaryReader = new BinaryReader(memoryStream);

                    if (byProtocol == 6)
                    {
                        
                        //The first sixten bits of the TCP header contain the Source Port
                        usSourcePort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                        //Next sixten bits of the TCP header contain the Destination Port
                        usDestinationPort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                        //Next 32 bits of the TCP header contain the Sequence Number
                        uiSequenceNumber = (uint)IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());

                        //Next 32 bits of the TCP header contain the Sequence Number
                        uiAcknowledgmentNumber = (uint)IPAddress.NetworkToHostOrder(binaryReader.ReadInt32());

                        //Next 16 bits of the TCP header contain the Data Offset and Flags
                        usDataOffsetAndFlags = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                        //Next 16 bits of the TCP header contain "Window size"
                        usWindowSize = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                        //Next 16 bits of the TCP header contain Checksum
                        sTCPUDPChecksum = (short)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                        //Next 16 bits of the TCP header contain Urgent Point
                        usUrgentPoint = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadUInt16());


                        //extracting TCP Header Length
                        usTCPHeaderLength = ExtractTCPHeaderlength(usDataOffsetAndFlags);

                        //Get FIN_Flag
                        FIN_Flag = GetBit(usDataOffsetAndFlags, 0);
                        //Get SYN_Flag
                        SYN_Flag = GetBit(usDataOffsetAndFlags, 1);
                        //Get RST_Flag
                        RST_Flag = GetBit(usDataOffsetAndFlags, 2);
                        //Get PSH_Flag
                        PSH_Flag = GetBit(usDataOffsetAndFlags, 3);
                        //Get ACK_Flag
                        ACK_Flag = GetBit(usDataOffsetAndFlags, 4);
                        //Get URG_Flag
                        URG_Flag = GetBit(usDataOffsetAndFlags, 5);
                        //Get ECE_Flag
                        ECE_Flag = GetBit(usDataOffsetAndFlags, 6);
                        //Get CWR_Flag
                        CWR_Flag = GetBit(usDataOffsetAndFlags, 7);
                        //Get NS_Flag
                        NS_Flag = GetBit(usDataOffsetAndFlags, 8);

                        //Next bits contains Params


                    } //TCP header


                    else if (byProtocol == 17)
                    {

                        //The first sixten bits of the UDP header contain the Source Port
                        usSourcePort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                        //Next sixten bits of the UDP header contain the Destination Port
                        usDestinationPort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                        //Next sixten bits of the UDP header contain the Datagram length
                        usDatagramLength = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                        //Next sixten bits of the UDP header contain the Checksum
                        sTCPUDPChecksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                        //Next bits contains data caried by UDP

                    }//UDP header


                }


                #endregion


            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message.ToString());

            }
        }







        private bool GetBit(ushort bits, int offset)
        {
            return (bits & (1 << offset)) != 0;
        }

        private ushort GetFromBits(ushort bits, int offset)
        {

            bits = (ushort)((bits << (offset - 1)));


            return (ushort)(bits >> (offset - 1));

        }

        private byte ExtractIPHeaderlength(byte bits)
        {

            //The last four bits of the version and header length field contain the
            //header length, we perform some simple binary arithmetic operations to
            //extract them
            bits <<= 4;
            bits >>= 4;
           //Multiply by four to get the exact header length
            bits *= 4;

            return bits;

        }

        private ushort ExtractTCPHeaderlength(ushort bits)
        {
            bits >>= 12;
            bits *= 4;
            return bits;

        }


    }
}
