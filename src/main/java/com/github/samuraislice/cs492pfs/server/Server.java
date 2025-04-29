package com.github.samuraislice.cs492pfs.server;

import com.github.samuraislice.cs492pfs.common.ConnectedClient;
import com.github.samuraislice.cs492pfs.common.PacketUtil;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Range;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Server implements AutoCloseable {

  private final Logger logger;
  private final int port;
  private final BiConsumer<@NotNull ConnectedClient, @NotNull String> listener;
  private final AtomicBoolean acceptingConnections = new AtomicBoolean(false);
  private final AtomicReference<Thread> serverThread = new AtomicReference<>();
  private final AtomicReference<ConnectedClient> currentClient = new AtomicReference<>();

  public Server(
      @Range(from = 0, to = 65535) int port,
      @NotNull BiConsumer<@NotNull ConnectedClient, @NotNull String> listener
  ) {
    this.listener = listener;
    this.logger = Logger.getLogger("PfsServer");
    this.port = port;
  }

  public void start() {
    if (!serverThread.compareAndSet(null, new ServerThread())) {
      // If the server thread is running already, deny.
      throw new IllegalStateException("Server is already running!");
    } else {
      // Otherwise, start server thread.
      this.acceptingConnections.set(true);
      serverThread.get().start();
    }
  }

  public void close() {
    // Stop accepting connections.
    this.acceptingConnections.set(false);
    Thread thread = this.serverThread.get();
    // Already shut down?
    if (thread == null) {
      return;
    }

    logger.info("Shutting down...");

    // Interrupt thread.
    thread.interrupt();

    int shutdownTimeout = 10;
    try {
      // Wait for thread to actually die.
      thread.join(TimeUnit.SECONDS.toMillis(shutdownTimeout));
    } catch (InterruptedException ignored) {
      // Current thread interrupted while waiting for server thread. A comedy of errors.
    }

    // If thread is alive, complain. Otherwise, all done!
    if (thread.isAlive()) {
      logger.warning(() -> String.format("Server thread failed to shut down after %d seconds!", shutdownTimeout));
    }
  }

  public @Nullable ConnectedClient getClient() {
    return this.currentClient.get();
  }

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
        serverThread.set(null);
        throw new RuntimeException(e);
      }
      serverThread.set(null);
    }

  }

  private void handleConnection(@NotNull Socket socket)
      throws GeneralSecurityException, IOException {
    socket.setSoTimeout((int) (PacketUtil.KEEPALIVE_INTERVAL * 2.5));
    socket.setKeepAlive(true); // TODO is this enough?

    // TODO Discuss: PFS without other stuff is largely useless, no guards against MitM etc.

    DataInputStream inputStream = new DataInputStream(socket.getInputStream());
    DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());

    byte[] sharedSecret = getSharedSecret(inputStream, outputStream);
    logger.fine(String.format("Agreed on shared key %s (%d bits)", new BigInteger(sharedSecret).toString(16), sharedSecret.length * Byte.SIZE));

    SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "AES");
    // TODO investigate other paddings
    Cipher encoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
    encoder.init(Cipher.ENCRYPT_MODE, keySpec);

    ConnectedClient client = new ConnectedClient(outputStream, encoder);
    currentClient.set(client);

    Cipher decoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
    decoder.init(Cipher.DECRYPT_MODE, keySpec);

    while (!socket.isClosed() && socket.isConnected()) {
      byte[] data = PacketUtil.readPacket(inputStream, logger);
      // TODO should use a signed quit or something.
      if (data.length == 1 && data[0] == -1) {
        break;
      }
      data = decoder.doFinal(data);

      if (data.length > 0) {
        listener.accept(client, new String(data, StandardCharsets.UTF_8));
      }
    }
  }

  private byte[] getSharedSecret(
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

}
