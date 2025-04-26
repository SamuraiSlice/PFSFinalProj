package CS492_Final_Proj;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.*;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;

public class PFSClient {

    // Constants for Diffie-Hellman parameters (prime and generator)
    private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67A26A8C8D96D7EEBC0CC6A024F76F7807E9EC3F7E0ECF5776B37B8F7C38313B0721D7B74258F9F3A3E5A57CCFE4C00C7590A7A0716E21226A2E1A128E2AB089410E58A4B348F32D82D2DCA46B72833B177F98E8E828EF2F79CC4A1661B4FE115D573073C37D1A788DD9F64090D39AA089E24C18A9789A302601199750053BC5F83C3A97123A35F5D49719D54F6A4416A263F7F0D10812204F8B98A89C971E43A65D9C6F76E08B8A17A8501C45DDBEF53CB616A1B9C9E3B6A256F8D9F8D07E46A6A2C14CC7E24B3B7A50F3D697C8D0D1A52D4419D19E03C536D27CC3450C22E8F9A208F242876C19DC3C6C2E1FE3E2567", 16);
    private static final BigInteger G = new BigInteger("2");
    private static final int NONCE_SIZE = 16;  // Size of nonce in bytes

    // Constants for cryptographic algorithms
    private static final String DH_ALGORITHM = "DH";
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) {
        try {
            // Connect to the server
            Socket socket = new Socket("localhost", 8443);
            DataInputStream inputStream = new DataInputStream(socket.getInputStream());
            DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());

            // Generate the client's Diffie-Hellman key pair
            KeyPair clientKeyPair = generateClientKeyPair();

            // Initialize the Diffie-Hellman key agreement
            KeyAgreement keyAgreement = initializeKeyAgreement(clientKeyPair);

            // Send client's public key to the server
            sendPublicKey(outputStream, clientKeyPair);
            System.out.println("Sent client's public key to the server");

            // Receive the server's public key
            PublicKey serverPublicKey = receiveServerPublicKey(inputStream);
            System.out.println("Received server's public key");

            // Perform Diffie-Hellman key exchange to generate shared secret
            byte[] sharedSecret = performKeyExchange(keyAgreement, serverPublicKey);

            // Generate and send the client's nonce to the server
            byte[] clientNonce = generateNonce();
            outputStream.writeInt(clientNonce.length);
            outputStream.write(clientNonce);
            System.out.println("Sent nonce to server");

            // Receive the server's nonce
            byte[] serverNonce = receiveNonce(inputStream);
            System.out.println("Received nonce from server");


            // Derive the encryption key from the shared secret and nonces
            SecretKeySpec encryptionKey = deriveEncryptionKey(sharedSecret);

            // Receive and decrypt the message from the server
            byte[] encryptedMessage = receiveEncryptedMessage(inputStream);
            System.out.println("Received encrypted message from server");

            String decryptedMessage = decryptMessage(encryptedMessage, encryptionKey);

            // Print the decrypted message
            System.out.println("Decrypted message from server: " + decryptedMessage);
            System.out.println("Decrypted message from server: " + decryptedMessage);


            socket.close();

        } catch (Exception e) {
            System.err.println("Client error: " + e.getMessage());
        }
    }

    /**
     * Generates the client's Diffie-Hellman key pair.
     */
    private static KeyPair generateClientKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(DH_ALGORITHM);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Initializes the Diffie-Hellman key agreement.
     */
    private static KeyAgreement initializeKeyAgreement(KeyPair keyPair) throws Exception {
        DHParameterSpec dhSpec = new DHParameterSpec(P, G);
        KeyAgreement keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM);
        keyAgreement.init(keyPair.getPrivate());
        return keyAgreement;
    }

    /**
     * Sends the client's public key to the server.
     */
    private static void sendPublicKey(DataOutputStream outputStream, KeyPair keyPair) throws IOException {
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        outputStream.writeInt(publicKeyBytes.length);
        outputStream.write(publicKeyBytes);
    }

    /**
     * Receives the server's public key.
     */
    private static PublicKey receiveServerPublicKey(DataInputStream inputStream) throws Exception {
        int length = inputStream.readInt();
        byte[] serverPublicKeyBytes = new byte[length];
        inputStream.readFully(serverPublicKeyBytes);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverPublicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(DH_ALGORITHM);
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * Performs Diffie-Hellman key exchange to generate shared secret.
     */
    private static byte[] performKeyExchange(KeyAgreement keyAgreement, PublicKey serverPublicKey) throws Exception {
        keyAgreement.doPhase(serverPublicKey, true);
        return keyAgreement.generateSecret();
    }

    /**
     * Generates a random nonce for the client.
     */
    private static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    /**
     * Receives the server's nonce.
     */
    private static byte[] receiveNonce(DataInputStream inputStream) throws IOException {
        int length = inputStream.readInt();
        byte[] nonce = new byte[length];
        inputStream.readFully(nonce);
        return nonce;
    }

    /**
     * Derives the encryption key from the shared secret using the first 16 bytes.
     */
    private static SecretKeySpec deriveEncryptionKey(byte[] sharedSecret) {
        return new SecretKeySpec(Arrays.copyOf(sharedSecret, 16), AES_ALGORITHM);
    }

    /**
     * Receives the encrypted message from the server.
     */
    private static byte[] receiveEncryptedMessage(DataInputStream inputStream) throws IOException {
        int length = inputStream.readInt();
        byte[] encryptedMessage = new byte[length];
        inputStream.readFully(encryptedMessage);
        return encryptedMessage;
    }

    /**
     * Decrypts the message using AES.
     */
    private static String decryptMessage(byte[] encryptedMessage, SecretKeySpec encryptionKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
        return new String(decryptedMessage);
    }
}
