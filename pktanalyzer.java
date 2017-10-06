
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class pktanalyzer {

	static StringBuilder hexData = new StringBuilder();
	static String IP = "0800";
	static int total_header_size = 0;
	@SuppressWarnings("resource")
	public static void main(String args[]) throws IOException 
	{
		if(args.length != 1) {
			System.out.println("Usage: java pktanalyzer /absolute_path_to_bin/xyz.bin");
			System.exit(0);
		}
		String filepath = args[0];
		File file = new File(filepath);
		int data_size = (int) file.length();
		int value = 0;

		FileInputStream fis;
		try {
			fis = new FileInputStream(new File(filepath));
		}
		finally {
			//pass
		}
		// array to the data of the file
		byte[] data = new byte[data_size];
		
		// read till the EOF
		do
	    {	
			value = fis.read(data);
	    }while(value != -1);
	
		// Converting the bin in to HexString
		for (int i=0;i<data.length;i++)
		{
		    String str  = Integer.toHexString(((data[i] >> 4) & 0x0f)) + Integer.toHexString((data[i] & 0x0f));
		    hexData.append(str);
		}
	    //System.out.println(hexData.toString());
	    ReadPacket(hexData, data_size);
	}
	/*
	 * As we know that in the IP packet first packet is all about Ethernet.
	 * So, we will parse the Ethernet Packet first and then we will proceed
	 * as follows:
	 * Ethernet header --> IP header --> UDP header/TCP header/ICMP header
	 * */
	public static void ReadPacket(StringBuilder hexData, int data_size) {

		icmp ICMP = new icmp();
		udp udp = new udp();
		ip ip = new ip();
		tcp tcp = new tcp();
		ethernet eth = new ethernet();
		
		String next_header = eth.ReadEthernetHeader(hexData, data_size);
		/*
		 * After reading the Ethernet Packet the next encapsulated protocol
		 * is returned in the var "next_header"
		 * */
		if(next_header.contains("IP")) {
			next_header = ip.ReadIPHeader(hexData, data_size);
		}
		if(next_header != null && next_header.contains("UDP")) {
			next_header = udp.ReadUDPHeader(hexData, data_size);
		}
		if(next_header != null && next_header.contains("TCP")) {
			next_header = tcp.ReadTCPHeader(hexData, data_size);
		}
		if(next_header != null && (next_header.contains("ICMP"))) {
			next_header = ICMP.ReadICMPHeader(hexData, data_size);
		}
	}
	
	public static void reset_parsing_buffer(StringBuilder buf_to_clear) {
		buf_to_clear.setLength(0);
	}
}
