import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class ServerCP1 {

    public static PrivateKey getServerPrivateKeyFromDerFile(String filename) throws Exception{
        
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename)); 
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec;)
    }

	public static void main(String[] args) {

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

            PrintWriter writer = new PrintWriter(connectionSocket.getOutputStream(), true);
            BufferedReader reader = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

			// Get oneTimeNonce from client
			int numBytesOneTimeNonce = fromClient.readInt();
			byte[] oneTimeNonce = new byte[numBytesOneTimeNonce]; 
			fromClient.readFully(oneTimeNonce, 0, numBytesOneTimeNonce);

			// Get private key 
			PrivateKey privateKey = getServerPrivateKeyFromDerFile("private_key.der");

			// Encrypt oneTimeNonce for client
            Cipher rsaCipher_encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher_encrypt.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encryptedNonce = rsaCipher_encrypt.doFinal(oneTimeNonce);

            toClient.writeInt(encryptedNonce.length);
            toClient.write(encryptedNonce);
            toClient.flush();

			// Send signed certificate to client
			InputStream fis = new FileInputStream("certificate_1004627.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate serverCert = (X509Certificate)cf.generateCertificate(fis);
			toClient.write(serverCert.getEncoded());
			toClient.flush(); 

			while(true){
				String readString = in.readLine();4
				if(readString.equals("NO HANDSHAKE")){ //fail verification
					toClient.close(); 
					fromClient.close();
					writer.close();
					reader.close();
					connectionSocket.close();
				}
			}

            while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.readFully(block, 0, numBytes);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

}
