package com.github.samuraislice.cs492pfs.client;

import com.github.samuraislice.cs492pfs.common.ConnectedClient;
import com.github.samuraislice.cs492pfs.common.PacketUtil;
import com.github.samuraislice.cs492pfs.server.Server;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

public abstract class Client implements AutoCloseable {

  private final Server server;

  public Client(@Range(from = 0, to = 65535) int port) {
    this.server = new Server(port, this::handleMessage);
  }

  public void start() {
    server.start();
  }

  public void connect(String address, int port) throws GeneralSecurityException, IOException {
    // TODO need a thread to not block
    //  Should also set server to not accept connections while connected here - shared?
    Socket socket = new Socket(address, port);
    DataInputStream inputStream = new DataInputStream(socket.getInputStream());
    DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());

    byte[] secret = getSharedSecret(inputStream, outputStream);

    // TODO encode/decode handling
  }

  private byte[] getSharedSecret(
      @NotNull DataInputStream inputStream,
      @NotNull DataOutputStream outputStream
  ) throws GeneralSecurityException, IOException {

    // Generate 2048-bit keypair.
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();

    // Send server prime, generator, and public key.
    PacketUtil.sendPacket(outputStream, keyPair.getPublic().getEncoded());

    // TODO establish logger (and do more logging)
    byte[] serverKeyData = PacketUtil.readPacket(inputStream, Logger.getLogger("PfsClient"));
    KeyFactory keyFactory = KeyFactory.getInstance("DH");
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverKeyData);
    PublicKey serverKey = keyFactory.generatePublic(keySpec);

    // Initialize key agreement.
    KeyAgreement agreement = KeyAgreement.getInstance("DH");
    agreement.init(keyPair.getPrivate());
    agreement.doPhase(serverKey, true);

    return agreement.generateSecret();
  }

  protected abstract void handleMessage(@NotNull ConnectedClient sender, @NotNull String message);

  @Override
  public void close() {
    server.close();
  }
}
