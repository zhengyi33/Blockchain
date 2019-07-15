//package blockchain;
/*1. Name / Date: Yi Zheng / 2.27.2019

2. Java version used, if not the official version for the class:

java se-10

3. Precise command-line compilation examples / instructions:


javac Blockchain.java
(for java 10) javac --add-modules java.xml.bind Blockchain.java

4. Precise examples / instructions to run this program:

java Blockchain 0 (or 1, 2 etc. for process id)
(for java 10) java --add-modules java.xml.bind Blockchain 0

5. List of files needed for running the program.

Blockchain.java*/

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.Serializable;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

class Ports{
	  public static int KeyServerPortBase = 4710;
	  public static int UnverifiedBlockServerPortBase = 4820;
	  public static int BlockchainServerPortBase = 4930;
	  //public static int StartPortBase = 5040;

	  public static int KeyServerPort;
	  public static int UnverifiedBlockServerPort;
	  public static int BlockchainServerPort;
	  //public static int StartPort;

	  public void setPorts(){//set port numbers for different processes
	    KeyServerPort = KeyServerPortBase + Blockchain.PID;
	    UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + Blockchain.PID;
	    BlockchainServerPort = BlockchainServerPortBase + Blockchain.PID;
	    //StartPort = StartPortBase + Blockchain.PID;
	  }
}

class PublicKeyWorker extends Thread {
	Socket sock; 
	PublicKeyWorker (Socket s) {sock = s;} 
	public void run(){
		try{
			//BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			//String data = in.readLine ();
			ObjectInputStream in = new ObjectInputStream(sock.getInputStream());
			
			PK pk = (PK) in.readObject();
			int pid = pk.pid;
			//Blockchain.pk_p0 = pk.public_key;
			
			//to get public keys
			if(pid == 0) {
				Blockchain.pk_p0 = pk.public_key;
			}
			else if(pid == 1) {
				Blockchain.pk_p1 = pk.public_key;
			}
			else if(pid == 2) {
				Blockchain.pk_p2 = pk.public_key;
			}
			//System.out.println("Got key: " + data);
			sock.close(); 
	    } catch (IOException | ClassNotFoundException x){x.printStackTrace();}
	}
}

class PublicKeyServer implements Runnable {
	public void run(){
		int q_len = 6;
		Socket sock;
		System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
		try{
			ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);//public key server listens for multicast of public keys
			while (true) {
				sock = servsock.accept();
				new PublicKeyWorker(sock).start(); 
			}
		}catch (IOException ioe) {System.out.println(ioe);}
	}
}

class DataTransformation{
	
	public static String marshal(BlockRecord br) {
		JAXBContext jaxbContext;
		String stringXML = null;
		try {
			jaxbContext = JAXBContext.newInstance(BlockRecord.class);

			Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
			StringWriter sw = new StringWriter();

			jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

			jaxbMarshaller.marshal(br, sw);
			stringXML = sw.toString();
		} catch (JAXBException e) {
			e.printStackTrace();
		}
		return stringXML;
	}
	
	public static BlockRecord unmarshal(String stringXML) {
		JAXBContext jaxbContext;
		BlockRecord blockRecord = null;
		try {
			jaxbContext = JAXBContext.newInstance(BlockRecord.class);
			Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
			StringReader reader = new StringReader(stringXML);
			blockRecord = (BlockRecord) jaxbUnmarshaller.unmarshal(reader);
		}catch (JAXBException e) {
			e.printStackTrace();
		}
		return blockRecord;
	}
}



class UnverifiedBlockServer implements Runnable {
	BlockingQueue<BlockRecord> queue;
	UnverifiedBlockServer(BlockingQueue<BlockRecord> queue){//reference of queue declared in main method is pass to local queue
		this.queue = queue; 
	}


	class UnverifiedBlockWorker extends Thread { 
		Socket sock; 
		UnverifiedBlockWorker (Socket s) {sock = s;} 
		public void run(){
			try{
				BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
				String data = "";
				String data2;
				while((data2 = in.readLine()) != null){//read marshaled data
					data = data + data2;
				}
				System.out.println("Put in priority queue: " + data + "\n");
				//should unmarshall data
				BlockRecord br = DataTransformation.unmarshal(data);
				queue.put(br);
				sock.close(); 
			} catch (Exception x){x.printStackTrace();}
		}
	}

	public void run(){
		int q_len = 6; 
		Socket sock;
		System.out.println("Starting the Unverified Block Server input thread using " +
				Integer.toString(Ports.UnverifiedBlockServerPort));
		try{
			ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
			while (true) {
				sock = servsock.accept(); // Got a new unverified block
				new UnverifiedBlockWorker(sock).start(); // So start a thread to process it.
			}
		}catch (IOException ioe) {System.out.println(ioe);}
	}
}

class RandomString { //create a random string

	static String getAlphaNumericString(int n) { 

		String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz"; 
 
		StringBuilder sb = new StringBuilder(n); 

		for (int i = 0; i < n; i++) { 

			int index = (int)(AlphaNumericString.length() * Math.random()); 

			sb.append(AlphaNumericString.charAt(index)); 
		} 

		return sb.toString(); 
	} 
}

class UnverifiedBlockConsumer implements Runnable {
	BlockingQueue<BlockRecord> queue;
	//int PID;
	UnverifiedBlockConsumer(BlockingQueue<BlockRecord> queue){
		this.queue = queue; // Constructor binds our prioirty queue to the local variable.
	}

	public void run(){
		BlockRecord br;
		PrintStream toServer;
		Socket sock;
		String newblockchain;
		String seed;
		String stringOut = null;
		int workNumber;
		String VerifiedBlock;
		String xmlString;
		PublicKey public_key = null;
		

		System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
		try{
			while(true) {//don't forget to verify!
				br=queue.take();
				String previous_bc = Blockchain.blockchainString;

				if(previous_bc.indexOf(br.BlockID)<0) {//if this block's uuid has not appeared in blockchain, thus not verified yet

					boolean solved = false;

					//verify block id is signed
					int creating_p_num = Integer.parseInt(br.CreatingProcess.substring(7));
					if (creating_p_num == 0) {public_key = Blockchain.pk_p0;}
					else if (creating_p_num == 1) {public_key = Blockchain.pk_p1;}
					else if (creating_p_num == 2) {public_key = Blockchain.pk_p2;}
					byte[] signature = Base64.getDecoder().decode(br.SignedBlockID);
					boolean verified = Blockchain.verifySig(br.BlockID.getBytes(), public_key, signature);
					System.out.println("Has the signed block ID been verified: " + verified + "\n");
					
					//verify sha256 hash is signed
					//byte[] sig_hash = Base64.getDecoder().decode(br.SignedSHA256);
					//verified = Blockchain.verifySig(br.SHA256String.getBytes(), public_key, sig_hash);
					//System.out.println("Has the signed SHA-256 hash been verified: " + verified + "\n");
					
					int beginIndex = previous_bc.indexOf("ABlockNum")+10;
					int endIndex = previous_bc.indexOf("</ABlockNum");
					String temp = previous_bc.substring(beginIndex, endIndex);
					Integer blocknum=Integer.parseInt(temp)+1;
					br.BlockNum = blocknum.toString();
					beginIndex=previous_bc.indexOf("ASHA256String")+14;
					endIndex=previous_bc.indexOf("</ASHA256String");
					String previoushash = previous_bc.substring(beginIndex, endIndex);
					br.PreviousHash = previoushash;
					br.VerificationProcessID = "Process "+Blockchain.PID;

					for(int i=0; i<100; i++) {
						seed = RandomString.getAlphaNumericString(8);
						//reset seed every iteration
						br.Seed = seed;
						xmlString = DataTransformation.marshal(br);
						MessageDigest MD = MessageDigest.getInstance("SHA-256");
						byte[] bytesHash = MD.digest(xmlString.getBytes("UTF-8")); 
						stringOut = DatatypeConverter.printHexBinary(bytesHash);
						System.out.println("Hash is: " + stringOut);
						workNumber = Integer.parseInt(stringOut.substring(0,4),16);
						System.out.println("First 16 bits " + stringOut.substring(0,4) +": " + workNumber + "\n");
						if (workNumber < 3000){
							System.out.println("Puzzle solved!");
							solved = true;
							//stringOut is the hash string
							br.SHA256String = stringOut;
							byte[] signature_current = Blockchain.signData(stringOut.getBytes(), Blockchain.key_pair.getPrivate());
							String signed_hash = Base64.getEncoder().encodeToString(signature_current);
							br.SignedSHA256 = signed_hash;
							System.out.println("The seed was: " + seed);
							break;
						}
					}
					
					//2 cases:
					//case1: block verified and blockchain not changed yet, then multi-cast
					//case2: no one verified block, then continue solving puzzle
					//other cases: discard block, move on to next block
					if(Blockchain.blockchainString.equals(previous_bc) && solved) {//if blockchain is not updated and puzzle solved; originally: if(Blockchain.blockchainString.indexOf(br.BlockID)<0 && Blockchain.blockchainString.equals(previous_br) && solved)
						Date date = new Date();
						String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
						String TimeStampString = T1 + "." + Blockchain.PID;
						xmlString = DataTransformation.marshal(br);
						VerifiedBlock = "[" + xmlString + " verified by P" + Blockchain.PID + " at time "+TimeStampString+"]\n";
						System.out.println(VerifiedBlock);
						String tempblockchain = VerifiedBlock + Blockchain.blockchainString;
						//System.out.println(tempblockchain);
						//multi-cast
						for (int i=0; i<Blockchain.numProcesses;i++) {
							sock = new Socket(Blockchain.serverName, Ports.BlockchainServerPortBase + i);
							toServer = new PrintStream(sock.getOutputStream());
							toServer.println(tempblockchain);
							toServer.flush();
							toServer.close();
						}
					}
					else if(Blockchain.blockchainString.indexOf(br.BlockID)<0 && !solved){//if the block is not verified by anyone, update block anyway whether the blockchain has been changed or not, then continue to work
						//if no one solved puzzle, check if blocknum and previous hash need to be updated
						queue.put(br);
					}
					Thread.sleep(1500);
				}
			}
			
		}catch (Exception e) {System.out.println(e);}
	}
}

class BlockchainWorker extends Thread { 
	Socket sock; 
	BlockchainWorker (Socket s) {sock = s;} 
	public void run(){
		try{
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			String data = "";
			String data2;
			while((data2 = in.readLine()) != null){
				data = data + data2;
			}
			//check for winner
			String current_bc = Blockchain.blockchainString;
			if (data.substring(data.indexOf("BlockID")+8,data.indexOf("</ABlockID")).equals(current_bc.substring(current_bc.indexOf("BlockID")+8,current_bc.indexOf("</ABlockID")))) {
				if (data.substring(data.indexOf("at time"),data.indexOf("]")).compareTo(current_bc.substring(current_bc.indexOf("at time"),current_bc.indexOf("]")))<0) {
					Blockchain.blockchainString = data;
				}
			}
			else {
				Blockchain.blockchainString = data;
			}
			if(Blockchain.PID == 0) {
				BufferedWriter writer = new BufferedWriter(new FileWriter("BlockchainLedger.xml"));
				writer.write(Blockchain.blockchainString);
				writer.close();
			}
			
			
			
			
			//System.out.println("         --NEW BLOCKCHAIN--\n" + Blockchain.blockchainString + "\n\n");
			sock.close(); 
		} catch (IOException x){x.printStackTrace();}
	}
}

class BlockchainServer implements Runnable {
	public void run(){
		int q_len = 6; 
		Socket sock;
		System.out.println("Starting the blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
		try{
			ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
			while (true) {
				sock = servsock.accept();
				new BlockchainWorker (sock).start(); 
			}
		}catch (IOException ioe) {System.out.println(ioe);}
	}
}


class PK implements Serializable{//use object stream to send public keys
	int pid;
	PublicKey public_key;
}

class CompareBR implements Comparator<BlockRecord>{

	@Override
	public int compare(BlockRecord br1, BlockRecord br2) {
		
		return br1.TimeStamp.compareTo(br2.TimeStamp);
	}
	
}

@XmlRootElement
class BlockRecord{//this class will be marshalled to send over the network
	String TimeStamp;
	String Seed;
	String BlockNum;
	String SHA256String;
	String SignedSHA256;
	String BlockID;
	String SignedBlockID;
	String VerificationProcessID;
	String CreatingProcess;
	String PreviousHash;
	String Fname;
	String Lname;
	String SSNum;
	String DOB;
	String Diag;
	String Treat;
	String Rx;

	/* Examples of accessors for the BlockRecord fields. Note that the XML tools sort the fields alphabetically
     by name of accessors, so A=header, F=Indentification, G=Medical: */
	
	public String getATimeStamp() {return TimeStamp;}
	@XmlElement
	public void setATimeStamp(String TimeStamp){this.TimeStamp = TimeStamp;}
	
	public String getAPreviousHash() {return PreviousHash;}
	@XmlElement
	public void setAPreviousHash(String PreviousHash){this.PreviousHash = PreviousHash;}
	
	public String getASeed() {return Seed;}
	@XmlElement
	public void setASeed(String Seed){this.Seed = Seed;}
	
	public String getABlockNum() {return BlockNum;}
	@XmlElement
	public void setABlockNum(String BN){this.BlockNum = BN;}
	
	public String getASHA256String() {return SHA256String;}
	@XmlElement
	public void setASHA256String(String SH){this.SHA256String = SH;}

	public String getASignedSHA256() {return SignedSHA256;}
	@XmlElement
	public void setASignedSHA256(String SH){this.SignedSHA256 = SH;}

	public String getACreatingProcess() {return CreatingProcess;}
	@XmlElement
	public void setACreatingProcess(String CP){this.CreatingProcess = CP;}

	public String getAVerificationProcessID() {return VerificationProcessID;}
	@XmlElement
	public void setAVerificationProcessID(String VID){this.VerificationProcessID = VID;}

	public String getABlockID() {return BlockID;}
	@XmlElement
	public void setABlockID(String BID){this.BlockID = BID;}
	
	public String getASignedBlockID() {return SignedBlockID;}
	@XmlElement
	public void setASignedBlockID(String SBID){this.SignedBlockID = SBID;}

	public String getFSSNum() {return SSNum;}
	@XmlElement
	public void setFSSNum(String SS){this.SSNum = SS;}

	public String getFFname() {return Fname;}
	@XmlElement
	public void setFFname(String FN){this.Fname = FN;}

	public String getFLname() {return Lname;}
	@XmlElement
	public void setFLname(String LN){this.Lname = LN;}

	public String getFDOB() {return DOB;}
	@XmlElement
	public void setFDOB(String DOB){this.DOB = DOB;}

	public String getGDiag() {return Diag;}
	@XmlElement
	public void setGDiag(String D){this.Diag = D;}

	public String getGTreat() {return Treat;}
	@XmlElement
	public void setGTreat(String D){this.Treat = D;}

	public String getGRx() {return Rx;}
	@XmlElement
	public void setGRx(String D){this.Rx = D;}

}


public class Blockchain {
	
	static String serverName = "localhost";
	static String blockchainString = "[First block]";
	//static ArrayList<BlockRecord> bcList = new ArrayList<>(); 
	static int numProcesses = 3; // Set this to match your batch execution file that starts N processes with args 0,1,2,...N
	static int PID = 0;
	static KeyPair key_pair = null;
	static PublicKey pk_p0;
	static PublicKey pk_p1;
	static PublicKey pk_p2;
	
	public static KeyPair generateKeyPair(long seed) throws Exception {
	    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
	    SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
	    rng.setSeed(seed);
	    keyGenerator.initialize(1024, rng);

	    return (keyGenerator.generateKeyPair());
	}
	
	public static void SendPK (){ // Multicast public key to each of the processes.
	    Socket sock;
	    //PrintStream toServer;
	    ObjectOutputStream toServer;
	    
	    PublicKey public_key = key_pair.getPublic();
	    PK pk = new PK();
	    pk.pid = PID;
	    pk.public_key = public_key;
	    
	    try{
	    	for(int i=0; i< numProcesses; i++){//send public keys to each process
	    		sock = new Socket(serverName, Ports.KeyServerPortBase + i);
	    		//toServer = new PrintStream(sock.getOutputStream());
	    		//toServer.println(PID); toServer.flush();
	    		toServer = new ObjectOutputStream(sock.getOutputStream());
	    		toServer.writeObject(pk); toServer.flush();
	    		sock.close();
	    	}
	    	Thread.sleep(1000);
	    }catch (Exception x) {x.printStackTrace ();}
	} 
	
	public static void marshall_send_unverified() {//mjulticast unverified blocks to processes
		int iFNAME = 0;
		int iLNAME = 1;
		int iDOB = 2;
		int iSSNUM = 3;
		int iDIAG = 4;
		int iTREAT = 5;
		int iRX = 6;
		String FILENAME;
		Socket sock;
		PrintStream toServer;
		switch(PID){
		case 1: FILENAME = "BlockInput1.txt"; break;
		case 2: FILENAME = "BlockInput2.txt"; break;
		default: FILENAME= "BlockInput0.txt"; break;
		}
		try {
			try (BufferedReader br = new BufferedReader(new FileReader(FILENAME))) {
				String[] tokens = new String[10];
				String stringXML;
				String InputLineStr;
				String suuid;
				UUID idA;

				BlockRecord[] blockArray = new BlockRecord[20];

				JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
				Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
				//StringWriter sw = new StringWriter();

				jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

				int n = 0;
				while ((InputLineStr = br.readLine()) != null) {
					StringWriter sw = new StringWriter();
					blockArray[n] = new BlockRecord();

					blockArray[n].setASHA256String("SHA string goes here...");
					blockArray[n].setASignedSHA256("Signed SHA string goes here...");
					blockArray[n].setASeed("seed goes here...");
					blockArray[n].setABlockNum("num goes here...");
					blockArray[n].setAPreviousHash("PreviousHash goes here...");

					
					idA = UUID.randomUUID();
					suuid = new String(UUID.randomUUID().toString());
					blockArray[n].setABlockID(suuid);
					byte[] signiture_uuid = signData(suuid.getBytes(),key_pair.getPrivate());
					String signed_uuid = Base64.getEncoder().encodeToString(signiture_uuid);
					blockArray[n].setASignedBlockID(signed_uuid);
					blockArray[n].setACreatingProcess("Process" + Integer.toString(PID));
					blockArray[n].setAVerificationProcessID("To be set later...");
					
					tokens = InputLineStr.split(" +"); 
					blockArray[n].setFSSNum(tokens[iSSNUM]);
					blockArray[n].setFFname(tokens[iFNAME]);
					blockArray[n].setFLname(tokens[iLNAME]);
					blockArray[n].setFDOB(tokens[iDOB]);
					blockArray[n].setGDiag(tokens[iDIAG]);
					blockArray[n].setGTreat(tokens[iTREAT]);
					blockArray[n].setGRx(tokens[iRX]);
					Date date = new Date();
				    String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
				    String TimeStampString = T1 + "." + PID;
					blockArray[n].setATimeStamp(TimeStampString);
					jaxbMarshaller.marshal(blockArray[n], sw);
					String fullBlock = sw.toString();
					
				    
				    //prepend time stamp for priority Q, maybe I should insert instead of prepending
				    //fullBlock = "time stamp: ("+TimeStampString+")"+fullBlock;
					System.out.println(fullBlock);
					for(int i=0; i< numProcesses; i++){//remember to change it back to numProcesses
						sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);
						toServer = new PrintStream(sock.getOutputStream());
						toServer.println(fullBlock); 
						toServer.flush();
						sock.close();
					}
					n++;
					Thread.sleep(1000);//make time stamps different
				}
				System.out.println(n + " records read.");
				System.out.println("Names from input:");
				for(int i=0; i < n; i++){
					System.out.println("  " + blockArray[i].getFFname() + " " +
							blockArray[i].getFLname());
				}
				System.out.println("\n");

				//stringXML = sw.toString();
				//for(int i=0; i < n; i++){
					
					//jaxbMarshaller.marshal(blockArray[i], sw);
				//}
				//String fullBlock = sw.toString();
				//System.out.println(fullBlock);
				//for(int i=0; i< numProcesses; i++){//remember to change it back to numProcesses
					//sock = new Socket(serverName, Ports.BlockchainServerPortBase + i);
					//toServer = new PrintStream(sock.getOutputStream());
					//toServer.println(fullBlock); 
					//toServer.flush();
					//sock.close();
				//}
			}catch (IOException e) {e.printStackTrace();}
		}catch (Exception e) {e.printStackTrace();}
	}
	
	public static byte[] signData(byte[] data, PrivateKey key) throws Exception { //data signing
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initSign(key);
		signer.update(data);
		return (signer.sign());
	}
	
	public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initVerify(key);
		signer.update(data);

		return (signer.verify(sig));
	}
	
	public static void main(String[] args) {
		int q_len = 6; 
		PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]); // Process ID
		System.out.println("Using processID " + PID + "\n");
		
		//test random
		/*for (int i=0; i<10; i++) {
			String seed = RandomString.getAlphaNumericString(8);
			System.out.println(seed);
		}*/
		
		CompareBR byTimeStamp = new CompareBR();
		final BlockingQueue<BlockRecord> queue = new PriorityBlockingQueue<>(16, byTimeStamp); // Concurrent queue for unverified blocks
		new Ports().setPorts();
		try {
			key_pair = generateKeyPair(999+PID);
		} catch (Exception e1) {
			e1.printStackTrace();
		}
		
		//test
		/*for (int i=0; i<10; i++) {
			String seed = RandomString.getAlphaNumericString(8);
			System.out.println(seed);
		}*/
		
		new Thread(new PublicKeyServer()).start();
		new Thread(new UnverifiedBlockServer(queue)).start();
		new Thread(new BlockchainServer()).start();

		try {Thread.sleep(5000);}catch(Exception e) {}//waiting here for 5 seconds for servers to start up

		SendPK(); //multicast public key

		//test code
		/*if(key_pair.getPublic().equals(pk_p0)) {
			System.out.println("key sent0");
		}
		if(key_pair.getPublic().equals(pk_p1)) {
			System.out.println("key sent1");
		}
		if(key_pair.getPublic().equals(pk_p2)) {
			System.out.println("key sent2");
		}
		if (pk_p0.equals(pk_p1)) {
			System.out.println("keys equal");
		}
		if (!pk_p0.equals(pk_p1)) {
			System.out.println("keys0,1 not equal");
		}*/

		//if(PID == 0) {//I'm trying to create a dummy first block using p0 here.
		try {
			JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
			Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
			StringWriter sw = new StringWriter();
			jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

			BlockRecord blockrecord = new BlockRecord();
			String dummyString = "abcdefghij";
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(dummyString.getBytes());
			byte[] byteData = md.digest();
			StringBuffer sb = new StringBuffer();
			for (int i=0; i<byteData.length; i++) {
				sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
			}
			String dummySHA256String = sb.toString();
			blockrecord.setASHA256String(dummySHA256String);
			byte[] digitalSignature = signData(dummySHA256String.getBytes(), key_pair.getPrivate());
			String dummySignedSHA256 = Base64.getEncoder().encodeToString(digitalSignature);
			blockrecord.setASignedSHA256(dummySignedSHA256);
			blockrecord.setABlockNum("0");
			String suuid = new String(UUID.randomUUID().toString());
			blockrecord.setABlockID(suuid);
			byte[] signature_dummy_uuid = signData(suuid.getBytes(),key_pair.getPrivate());
			String signed_dummy_uuid = Base64.getEncoder().encodeToString(signature_dummy_uuid);
			blockrecord.setASignedBlockID(signed_dummy_uuid);
			blockrecord.setACreatingProcess("Process0");
			blockrecord.setAVerificationProcessID("Process0");
			blockrecord.setFSSNum("123-45-6789");
			blockrecord.setFFname("John");
			blockrecord.setFLname("Smith");
			blockrecord.setFDOB("1990.01.01");
			blockrecord.setGDiag("Obesity");
			blockrecord.setGTreat("HeathyFoods");
			blockrecord.setGRx("Aspirin");
			//bcList.add(blockrecord);
			String stringXML = sw.toString();
			jaxbMarshaller.marshal(blockrecord, sw);
			String fullBlock = sw.toString();
			String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
			String cleanBlock = fullBlock.replace(XMLHeader, "");
			String XMLBlock = XMLHeader + "\n<BlockLedger>" + cleanBlock + "</BlockLedger>";//maybe add header and ledger tag in the end
			if(PID == 0) {
				BufferedWriter writer = new BufferedWriter(new FileWriter("BlockchainLedger.xml"));
				writer.write(XMLBlock);
				writer.close();
			}
			blockchainString = XMLBlock;
			
			/*Socket sock;
			PrintStream toServer;
			for(int i=0; i< numProcesses; i++){
				sock = new Socket(serverName, Ports.BlockchainServerPortBase + i);
				toServer = new PrintStream(sock.getOutputStream());
				toServer.println(fullBlock); 
				toServer.flush();
				sock.close();
			}*/
			Thread.sleep(1000);
		}catch(Exception x) {x.printStackTrace();}
		
		marshall_send_unverified();
		new Thread(new UnverifiedBlockConsumer(queue)).start();
	}

}
