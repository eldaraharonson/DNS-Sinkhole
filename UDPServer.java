package il.ac.idc.cs.sinkhole;

import java.io.*;
import java.net.*;
import java.util.HashSet;
import java.util.Random;

public class UDPServer {
    private static String domainName;
    private static final int PORT = 5300;
    public DatagramSocket socket;
    InetAddress sourceAddress;
    DatagramPacket DNSResponse = null;
    HashSet<String> blockList = null;
    Client client;
    DatagramPacket queryAnswerPacket;

    public UDPServer() throws Exception {
        this.socket = new DatagramSocket(PORT);
        this.client = new Client();
    }

    // Overloaded constructor with option of blockList
    public UDPServer(HashSet<String> blockListDomains) throws Exception {
        this.socket = new DatagramSocket(PORT);
        this.client = new Client();
        this.blockList = blockListDomains;
    }

    public void run() throws Exception {
        Query query = new Query(socket);
        while (true) {
            try {
                query.getRequest(); //Get DNS request from client
                domainName = query.getDomainName();
                if (this.blockList != null) {
                    // checks if the domain sent is in the blockList
                    if (this.blockList.contains(domainName)) {
                        sendNameError(query.receivePacket);
                    }
                }
                sourceAddress = query.getSourceAddress();
            }
            catch (Exception e) {
                System.err.println("Couldn't receive dig request");
            }
            try {
                InetAddress RandomRootServer = InetAddress.getByName(query.getRandomRootServerHostName());
                client.sendRequest(RandomRootServer); //Forward the request to one of the root servers
                DNSResponse = client.getResponse();
                Answer ans = new Answer();
                queryAnswerPacket = ans.analyseAnswers(DNSResponse, client);
                socket.send(buildUserPacket(queryAnswerPacket, query));
            }
            catch (Exception e) {
                System.err.println("Couldn't send request and get response from Random root server");
            }
        }
    }

    public static String getDomainName() {
        return domainName;
    }

    // Sends back a "Name Error" response
    private void sendNameError(DatagramPacket packet) throws Exception {
        byte[] data = packet.getData();
        data[2] = (byte) ((data[2] & -5) | 0b10000000);
        data[3] = (byte) (((data[3] | 0b10000000) & 0b11110000) | 3);
        DatagramPacket packetToSend = new DatagramPacket(data, packet.getLength(), packet.getAddress(), packet.getPort());
        this.socket.send(packetToSend);
    }

    // Creates the packet that will be sent back to the client
    private DatagramPacket buildUserPacket(DatagramPacket datagramPacket, Query query) throws Exception {
        byte[] data = datagramPacket.getData();
        data[2] = (byte) ((data[2] & -5) | 0b10000000);
        data[3] = (byte) (data[3] | 0b10000000);
        int destPort = query.getDestPort();
        InetAddress destAddress = query.getSourceAddress();
        DatagramPacket packet = new DatagramPacket(data, datagramPacket.getLength(), destAddress, destPort);

        return packet;
    }
}
    class Client {
        DatagramSocket socket;
        private static final int DNS_PORT = 53;
        public Client() {
            try {
                this.socket = new DatagramSocket(DNS_PORT);
            }
            catch (SocketException e) {
                e.printStackTrace();
            }
        }

        void sendRequest(InetAddress nextAddress) throws IOException {
            //Sends request to a predefined root server
            String domain = UDPServer.getDomainName();
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);

            //Constructing the query
            dataOutputStream.writeShort(0x1234);
            dataOutputStream.writeShort(0x0000);
            dataOutputStream.writeShort(0x0001);
            dataOutputStream.writeShort(0x0000);
            dataOutputStream.writeShort(0x0000);
            dataOutputStream.writeShort(0x0000);

            String[] domainParts = domain.split("\\.");		//Splits given domian wrt '.'
            for (int i = 0; i < domainParts.length; i++) {
                byte[] domainBytes = domainParts[i].getBytes("UTF-8");
                dataOutputStream.writeByte(domainBytes.length);
                dataOutputStream.write(domainBytes);
            }

            dataOutputStream.writeByte(0x00);
            dataOutputStream.writeShort(0x0001);
            dataOutputStream.writeShort(0x0001);

            byte[] dnsFrameByteArray = byteArrayOutputStream.toByteArray();
            DatagramPacket datagramPacket = new DatagramPacket(dnsFrameByteArray, dnsFrameByteArray.length, nextAddress, DNS_PORT);
            socket.send(datagramPacket);	//Send the request to obtained IP address
        }

        public DatagramPacket getResponse() throws IOException {
            byte[] receivedData = new byte[1024];
            DatagramPacket DNSResponse = new DatagramPacket(receivedData, receivedData.length);
            socket.receive(DNSResponse);
            return DNSResponse;
        }
    }

    //Class to send query and receive response
    class Query {
        DatagramSocket socket;
        String[] rootServers;
        byte[] receiveData = new byte[1024];
        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

        public Query(DatagramSocket skt) {
            this.socket = skt;
            this.rootServers = getAllRootServers();
        }

        void getRequest() throws IOException {
            socket.receive(receivePacket);
        }

        public String extractDomainName(DatagramPacket query) {
            int position = 12;
            byte[] data = query.getData();
            byte numberOfBytesInDomainName = data[position];
            StringBuilder domainName = new StringBuilder();
            while (numberOfBytesInDomainName > 0) {
                for (int i = 1; i <= numberOfBytesInDomainName; i++) {
                    char nextLetter = (char) data[position + i];
                    domainName.append(nextLetter);
                }
                position += numberOfBytesInDomainName + 1;
                numberOfBytesInDomainName = data[position];
                domainName.append(".");
            }

            return domainName.substring(0, domainName.length() - 1);
        }

        public String getDomainName() {
            return extractDomainName(receivePacket);
        }

        public InetAddress getSourceAddress() {
            return receivePacket.getAddress();
        }

        int getDestPort() throws IOException {
            return receivePacket.getPort();
        }

        private String[] getAllRootServers() {
            //Initializes 13 root servers
            rootServers = new String[13];
            rootServers[0] = "a.root-servers.net";
            rootServers[1] = "b.root-servers.net";
            rootServers[2] = "c.root-servers.net";
            rootServers[3] = "d.root-servers.net";
            rootServers[4] = "e.root-servers.net";
            rootServers[5] = "f.root-servers.net";
            rootServers[6] = "g.root-servers.net";
            rootServers[7] = "h.root-servers.net";
            rootServers[8] = "i.root-servers.net";
            rootServers[9] = "j.root-servers.net";
            rootServers[10] = "k.root-servers.net";
            rootServers[11] = "l.root-servers.net";
            rootServers[12] = "m.root-servers.net";
            return rootServers;
        }

        public String getRandomRootServerHostName() {
            Random random = new Random();
            int randomInt = random.nextInt(13);
            return this.rootServers[randomInt];
        }
    }

    class Answer {
        //Class to analyse the response
        private static final int MAX_REQUESTS = 15;
        InetAddress nextAddress = null;

        DatagramPacket analyseAnswers(DatagramPacket DNSResponse, Client client) throws Exception {
            while (true) {
                int requestsNumber = 0;
                while (finalAddressNotFound(DNSResponse) && requestsNumber <= MAX_REQUESTS) {
                    try {
                        nextAddress = getFirstAuthority(DNSResponse);
                    }
                    catch (Exception e) {
                        System.err.println("Couldn't get address from response's RData");
                    }

                    try {
                        client.sendRequest(nextAddress);
                       DNSResponse = client.getResponse();
                    }
                    catch (Exception e) {
                        System.err.println("Failed to send/receive packet while sending to querying servers");
                        break;
                    }

                    requestsNumber++;
                }
                // If the domain doesn't exist
                if (!(isNumOfAnswersIsZero(DNSResponse) && isResponseCodeNOERROR(DNSResponse))) {
                    return DNSResponse;
                }
            }
        }

        // Returns the first authorative IP address found in the response packet from the server
        private InetAddress getFirstAuthority(DatagramPacket datagramPacket) throws Exception {
            String address = getAddressFromData(datagramPacket, getRdataOfFirstServer(datagramPacket));
            return InetAddress.getByName(address);
        }

        // Returns the domain name of the packet
        private String getAddressFromData(DatagramPacket datagramPacket, int startPosition) {
            byte[] data = datagramPacket.getData();
            StringBuilder address = new StringBuilder();
            int position = startPosition;
            byte numBytesToRead = data[position];
            while (numBytesToRead != 0) {
                if ((numBytesToRead & -64) == -64) {
                    position = (numBytesToRead & 63) << 8 | data[position + 1];
                    numBytesToRead = data[position];
                    continue;
                }
                for (int i = 1; i <= numBytesToRead; i++) {
                    address.append((char) data[position + i]);
                }

                position += numBytesToRead + 1;
                numBytesToRead = data[position];
                address.append(".");
            }

            return address.substring(0, address.length() - 1);
        }

        private int getRdataOfFirstServer(DatagramPacket datagramPacket) {
            byte[] responseData = datagramPacket.getData();
            int iterator = 12; //Header size;

            // Skip il.ac.idc.cs.sinkhole.Query fields
            while (responseData[iterator] != 0) {
                iterator++;
            }
            iterator += 5;

            // while still on RR format
            while (responseData[iterator] != 0) {
                iterator++;
            }

            iterator += 10; //  11 bytes are separating between the last byte of the name to the begin of the RData
            return iterator;
        }

        private boolean isResponseCodeNOERROR(DatagramPacket datagramPacket) {
            byte[] data = datagramPacket.getData();
            //Check if the error code is 0 as expected
            return (data[3] & 15) == 0;
        }

        // Returns whether the final IP address has been found
        private boolean finalAddressNotFound(DatagramPacket datagramPacket) {
            return isResponseCodeNOERROR(datagramPacket) &&
                    isNumOfAnswersIsZero(datagramPacket) &&
                    isNumOfAuthoritiesDifferentThanZero(datagramPacket);
        }


        private boolean isNumOfAnswersIsZero(DatagramPacket datagramPacket) {
            byte[] data = datagramPacket.getData();
            return (data[6] << 8 | data[7]) == 0;
        }

        // Returns if at least one authorative server has been returned
        private boolean isNumOfAuthoritiesDifferentThanZero(DatagramPacket datagramPacket) {
            byte[] data = datagramPacket.getData();
            return (data[8] << 8 | data[9]) > 0;
        }
    }



