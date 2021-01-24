import java.io.*;
import java.util.HashSet;
import il.ac.idc.cs.sinkhole.*;
public class SinkholeServer {
    private static UDPServer udpServer;


    public static void closeConnection() throws Exception {
        udpServer.socket.close();
    }

    public static void main(String[] args) throws Exception {
        // if blocklist.txt is sent as an argument
        if (args.length == 1) {
            HashSet<String> blockListDomains = getSetOfBlockedDomains(args[0]);
            udpServer = new UDPServer(blockListDomains);
        }
        else {
            udpServer = new UDPServer();
        }
        udpServer.run();
    }

    // returns a HashSet of all URLs in blocklist.txt
    public static HashSet<String> getSetOfBlockedDomains(String filePath) {
        HashSet<String> blockListDomains = new HashSet<String>();
        try {
            BufferedReader bf = new BufferedReader(new FileReader(filePath));
            String domain = bf.readLine();
            while (domain != null) {
                blockListDomains.add(domain);
                domain = bf.readLine();
            }
            bf.close();

        }
        catch (Exception e) {
            System.err.println("Error accessing file");
        }
        return blockListDomains;
    }
}
