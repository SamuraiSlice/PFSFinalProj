package com.github.samuraislice.cs492pfs.server;

import com.github.samuraislice.cs492pfs.common.Connection;
import com.github.samuraislice.cs492pfs.common.CryptoConstants;
import com.github.samuraislice.cs492pfs.common.PacketUtil;
import com.github.samuraislice.cs492pfs.common.Remote;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.ServerSocketChannel;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

public class ServerConnection extends Connection {

  private final int port;
  protected final AtomicBoolean acceptingConnections = new AtomicBoolean();

  public ServerConnection(
      @NotNull String identity,
      @NotNull BiConsumer<@NotNull Remote, @NotNull String> listener,
      @Range(from = 0, to = 65535) int port
  ) {
    super(identity, listener);
    this.port = port;
  }

  public boolean isAcceptingConnections() {
    return this.acceptingConnections.get();
  }

  @Override
  public void open() {
    if (!connectionThread.compareAndSet(null, new ServerThread())) {
      // If the server thread is running already, deny.
      throw new IllegalStateException("ServerConnection is already running!");
    } else {
      // Otherwise, start server thread.
      this.acceptingConnections.set(true);
      connectionThread.get().start();
    }
  }

  @Override
  public void close() {
    // Stop accepting connections.
    this.acceptingConnections.set(false);
    super.close();
  }

  @Override
  protected byte[] getSharedSecret(
      @NotNull DataInputStream inputStream,
      @NotNull DataOutputStream outputStream
  ) throws GeneralSecurityException, IOException {

    logger.fine("Awaiting parameters...");
    // Recieve client data. This contains prime, generator, and public key information.
    byte[] data = PacketUtil.readPacket(inputStream, logger);
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(data);
    KeyFactory factory = KeyFactory.getInstance(CryptoConstants.SHARED_KEY_AGREEMENT);
    PublicKey clientKey = factory.generatePublic(keySpec);
    logPubKey("Their key", clientKey);

    if (!(clientKey instanceof DHPublicKey dhPubKey)) {
      throw new IOException("Invalid key parameters!");
    }

    // Initialize keypair using given prime and generator.
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.SHARED_KEY_AGREEMENT);
    keyGen.initialize(dhPubKey.getParams());
    KeyPair keyPair = keyGen.generateKeyPair();
    PublicKey serverKey = keyPair.getPublic();
    logPubKey("Our key", serverKey);

    // Send client the server public key.
    PacketUtil.sendPacket(outputStream, serverKey.getEncoded());

    KeyAgreement agreement = KeyAgreement.getInstance(CryptoConstants.SHARED_KEY_AGREEMENT);
    agreement.init(keyPair.getPrivate());
    agreement.doPhase(clientKey, true);

    return agreement.generateSecret();
  }

  private class ServerThread extends Thread {

    ServerThread() {
      super("PfsServer");
    }

    @Override
    public void run() {
      logger.info(() -> String.format("Starting server on port %d...", port));
      try (ServerSocketChannel channel = ServerSocketChannel.open().bind(new InetSocketAddress(port));
          ServerSocket socket = channel.socket()) {
        while (acceptingConnections.get() && !interrupted()) {
          logger.info("Listening for connections.");
          try (Socket client = socket.accept()) {
            logger.info(() -> String.format("Accepted connection from %s",
                client.getRemoteSocketAddress()));
            handleConnection(client);
          } catch (ClosedByInterruptException e) {
            // Thread interrupted. Shutting down.
            logger.info("Stopped waiting for connections.");
          } catch (Exception e) {
            currentClient.set(null);
            logger.info(() -> "Client disconnected: " + e.getMessage());
            logger.log(Level.FINE, "Client disconnection", e);
          }
        }
      } catch (IOException e) {
        logger.info(() -> "Server closed: " + e.getMessage());
        logger.log(Level.FINE, "Server closure", e);
      }
      currentClient.set(null);
      connectionThread.set(null);
    }

  }

}
