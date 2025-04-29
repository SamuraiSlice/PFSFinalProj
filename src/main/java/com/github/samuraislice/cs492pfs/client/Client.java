package com.github.samuraislice.cs492pfs.client;

import com.github.samuraislice.cs492pfs.common.Remote;
import com.github.samuraislice.cs492pfs.common.Connection;
import com.github.samuraislice.cs492pfs.common.PacketUtil;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;
import org.jetbrains.annotations.NotNull;

public class Client extends Connection {

  public Client(
      @NotNull BiConsumer<@NotNull Remote, @NotNull String> listener
  ) {
    this(listener, new AtomicBoolean());
  }

  public Client(
      @NotNull BiConsumer<@NotNull Remote, @NotNull String> listener,
      @NotNull AtomicBoolean acceptingConnections
  ) {
    super(Logger.getLogger("PfsClient"), listener, acceptingConnections);
  }

  @Override
  public void open() {
    // TODO accept address and port in constructor, make this connect?
    // TODO need a thread
    //  might want to add a getThread method or similar to extract common code with server
  }

  public void connect(String address, int port) throws GeneralSecurityException, IOException {
    if (!acceptingConnections.compareAndSet(false, true)) {
      return;
    }
    try (Socket socket = new Socket(address, port)) {
      handleConnection(socket);
    } catch (GeneralSecurityException | IOException e) {
      acceptingConnections.set(true);
      throw e;
    }
    acceptingConnections.set(true);
  }

  @Override
  protected byte[] getSharedSecret(
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

}
