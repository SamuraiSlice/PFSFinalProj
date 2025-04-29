package com.github.samuraislice.cs492pfs.server;

import com.github.samuraislice.cs492pfs.common.Remote;
import com.github.samuraislice.cs492pfs.common.Connection;
import com.github.samuraislice.cs492pfs.common.PacketUtil;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

public class Server extends Connection {

  private final int port;

  public Server(
      @Range(from = 0, to = 65535) int port,
      @NotNull BiConsumer<@NotNull Remote, @NotNull String> listener
  ) {
    this(port, listener, new AtomicBoolean());
  }

  public Server(
      @Range(from = 0, to = 65535) int port,
      @NotNull BiConsumer<@NotNull Remote, @NotNull String> listener,
      @NotNull AtomicBoolean acceptingConnections
  ) {
    super(Logger.getLogger("PfsServer"), listener, acceptingConnections);
    this.port = port;
  }

  @Override
  public void open() {
    if (!connectionThread.compareAndSet(null, new ServerThread())) {
      // If the server thread is running already, deny.
      throw new IllegalStateException("Server is already running!");
    } else {
      // Otherwise, start server thread.
      this.acceptingConnections.set(true);
      connectionThread.get().start();
    }
  }

  // TODO extract to common class

  @Override
  protected byte[] getSharedSecret(
      @NotNull DataInputStream inputStream,
      @NotNull DataOutputStream outputStream
  ) throws GeneralSecurityException, IOException {

    logger.fine("Awaiting DH parameters");
    // Recieve client data. This contains prime, generator, and public key information.
    byte[] data = PacketUtil.readPacket(inputStream, logger);
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(data);
    // TODO might be "DiffieHellman" for init (though algorithm returns "DH")
    // https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#keyfactory-algorithms
    KeyFactory factory = KeyFactory.getInstance("DH");
    PublicKey clientKey = factory.generatePublic(keySpec);

    if (!(clientKey.getParams() instanceof DHParameterSpec params)) {
      throw new IOException("Invalid key parameters!");
    }

    // Initialize keypair using given prime and generator.
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
    keyGen.initialize(params);
    KeyPair keyPair = keyGen.generateKeyPair();

    // Send client the server public key.
    logger.fine("Sending DH public key");
    PacketUtil.sendPacket(outputStream, keyPair.getPublic().getEncoded());

    KeyAgreement agreement = KeyAgreement.getInstance("DH");
    agreement.init(keyPair.getPrivate());
    agreement.doPhase(clientKey, true);

    logger.fine("Generating shared secret.");
    return agreement.generateSecret();
  }

  // TODO maybe extract to separate class
  private class ServerThread extends Thread {

    ServerThread() {
      super("PfsServer");
    }

    @Override
    public void run() {
      logger.info(() -> String.format("Starting server on port %d...", port));
      try (ServerSocket socket = new ServerSocket(port)) {
        while (acceptingConnections.get() && !interrupted()) {
          logger.info("Listening for connections.");
          try (Socket client = socket.accept()) {
            logger.info(() -> String.format("Accepted connection from %s", client.getRemoteSocketAddress()));
            handleConnection(client);
          } catch (Exception e) {
            currentClient.set(null);
            // TODO log handling
            logger.info("Client disconnected!");
            logger.log(Level.FINE, "Client disconnection", e);
          }
        }
      } catch (IOException e) {
        connectionThread.set(null);
        throw new RuntimeException(e);
      }
      connectionThread.set(null);
    }

  }

}
