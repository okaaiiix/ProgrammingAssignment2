import java.io.BufferedInputStream;
import java.io.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Random;
import java.util.Arrays;
import java.util.Base64;

public class ClientCP1 {


    public static PublicKey getServerPublicKeyFromDerFile(String filename) throws Exception{
        
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename)); 
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public static PublicKey getServerPublicKeyFromCertAndVerifyKey(X509Certificate serverCert) throws Exception{
        // Get server public key 
		PublicKey serverKey = serverCert.getPublicKey();
		//PublicKey serverKey = getPublicKey(public_key.der); 
//TESTING ON GETTING KEYS - SERVER       
        
        // Create X509Certificate object of CAcert
		InputStream fis = new FileInputStream("cacsertificate.crt");
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate CAcert = (X509Certificate)cf.generateCertificate(fis);

		// Extract CA Public Key from X509Certificate Object 
		PublicKey p_key = CAcert.getPublicKey();

		// Check validity and verify signed certificate
		CAcert.checkValidity();
		CAcert.verify(p_key);

        return serverKey; 
    }

	public static void main(String[] args) {

        String serverAddress = "localhost"; 
        int port = 4321;

        // Send multiple files 
        String[] filenames = {"100.txt", "200.txt", "500.txt", "1000.txt", "5000.txt", "10000.txt", "50000.txt", "100000.txt"}; 
        if(args.length > 0){
            filenames = new String[args.length];
            for(int i = 0; i < args.length; i++){
                filenames[i] = args[i];
            }
        }

//THESE NO LONGER REQUIRED? 
    	// String filename = "100.txt"; 
    	// if (args.length > 0) filename = args[0];

    	// //String serverAddress = "localhost";
    	// if (args.length > 1) filename = args[1];

    	// //int port = 4321;
    	// if (args.length > 2) port = Integer.parseInt(args[2]);

		//int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		
		

		try {

			System.out.println("Establishing connection to server...");

//ADDER TO THE TOP 
			// // Create X509Certificate object
			// InputStream fis = new FileInputStream("cacsertificate.crt");
			// CertificateFactory cf = CertificateFactory.getInstance("X.509");
			// X509Certificate CAcert = (X509Certificate)cf.generateCertificate(fis);

			// //Extract Public Key from X509Certificate Object
			// PublicKey p_key = CAcert.getPublicKey();

			// // Check validity and verify signed certificate
			// CAcert.checkValidity();
			// CAcert.verify(p_key);

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

            PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            // Get oneTimeNonce for server
            System.out.println("Generating and sending nonce to server...");
            byte[] oneTimeNonce = new byte[32]; 
            new Random(). nextBytes(oneTimeNonce);
            toServer.writeInt(oneTimeNonce.length);
            toServer.write(oneTimeNonce);
            toServer.flush(); 

            // Get encrypted oneTimeNonce from server 
            int numBytesEncryptedNonce = fromServer.readInt();
            byte[] encryptedNonce = new byte[numBytesEncryptedNonce]; 
            fromServer.readFully(encryptedNonce, 0, numBytesEncryptedNonce);

            // Create X509Certificate object of serverCert
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate serverCert = (X509Certificate)cf.generateCertificate(fromServer);
            
            // Extract Server Public Key from X509Certificate Object
            PublicKey server_p_key = getServerPublicKeyFromCertAndVerifyKey(serverCert);

            // Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as decrypt mode, use PUBLIC key
            Cipher rsaCipher_decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher_decrypt.init(Cipher.DECRYPT_MODE, server_p_key);
                     
            // Decrypte encrypted oneTimeNonce
            byte[] decryptedNonce = rsaCipher_decrypt.doFinal(encryptedNonce);

            // Verify decrypted oneTimeNonce - if not equal, fail
            if(!Arrays.equals(oneTimeNonce, decryptedNonce)){
				writer.println("NO HANDSHAKE");
                toServer.close(); 
                fromServer.close();
                writer.close();
                reader.close();
                clientSocket.close();
            }

            System.out.println("Sending file...");
            
            // For sending multiple files
            for(int i = 0; i < filenames.length; i++){

			    // Send the filename
			    toServer.writeInt(0);
			    toServer.writeInt(filenames[i].getBytes().length);
			    toServer.write(filenames[i].getBytes());
			    toServer.flush();

			    // Open the file
			    fileInputStream = new FileInputStream(filenames[i]);
			    bufferedFileInputStream = new BufferedInputStream(fileInputStream);

	            byte [] fromFileBuffer = new byte[117];

                int numBytes = 0;
                int numBytesEncrypted = 0; 

	            // Send the file
	            for (boolean fileEnded = false; !fileEnded;) {
			        numBytes = bufferedFileInputStream.read(fromFileBuffer);
				    fileEnded = numBytes < 117;

                    //Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as encrypt mode, use PRIVATE key.
                    Cipher rsaCipher_encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsaCipher_encrypt.init(Cipher.ENCRYPT_MODE, server_p_key);

                    // Encrypt file
                    byte[] encryptedFile = rsaCipher_encrypt.doFinal(fromFileBuffer); 
                    
                    numBytesEncrypted = encryptedFile.length; 

				    toServer.writeInt(1);
				    toServer.writeInt(numBytes);
				    toServer.write(encryptedFile);
				    toServer.flush();
			    }

	            bufferedFileInputStream.close();
	            fileInputStream.close();

            }

            toServer.writeInt(2); // file sent

//SEND TO THE FOR LOOP FOR MULTIPLE FILES
			// // Send the filename
			// toServer.writeInt(0);
			// toServer.writeInt(filename.getBytes().length);
			// toServer.write(filename.getBytes());
			// //toServer.flush();

			// // Open the file
			// fileInputStream = new FileInputStream(filename);
			// bufferedFileInputStream = new BufferedInputStream(fileInputStream);

	        // byte [] fromFileBuffer = new byte[117];

	        // // Send the file
	        // for (boolean fileEnded = false; !fileEnded;) {
			// 	numBytes = bufferedFileInputStream.read(fromFileBuffer);
			// 	fileEnded = numBytes < 117;

			// 	toServer.writeInt(1);
			// 	toServer.writeInt(numBytes);
			// 	toServer.write(fromFileBuffer);
			// 	toServer.flush();
			// }

	        // bufferedFileInputStream.close();
	        // fileInputStream.close();

			System.out.println("Closing connection...");

            toServer.close(); 
            fromServer.close();
            writer.close();
            reader.close();
            clientSocket.close();

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
}
