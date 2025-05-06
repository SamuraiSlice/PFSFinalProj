package com.github.samuraislice.cs492pfs.common;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Abstraction representing a connection to a remote client or server.
 */
public abstract class Connection implements AutoCloseable {

  protected final Logger logger = Logger.getLogger(getClass().getName());
  protected final AtomicReference<Thread> connectionThread = new AtomicReference<>();
  protected final AtomicReference<Remote> currentClient = new AtomicReference<>();
  private final String identity;
  private final BiConsumer<@NotNull Remote, @NotNull String> listener;

  protected Connection(@NotNull String identity, @NotNull BiConsumer<@NotNull Remote, @NotNull String> listener) {
    this.identity = identity;
    this.listener = listener;
  }

  /**
   * Get the identity in use on this connection.
   *
   * @return the identity
   */
  public @NotNull String getIdentity() {
    return this.identity;
  }

  /**
   * Initiate connection.
   */
  public abstract void open();

  /**
   * Handle a connection.
   *
   * @param socket the connected socket
   * @throws GeneralSecurityException if a handshaking or decoding issue occurs
   * @throws IOException if a communication issue occurs
   */
  protected void handleConnection(@NotNull Socket socket)
      throws GeneralSecurityException, IOException {
    // TODO enable timeout and do keepalives
    //socket.setSoTimeout((int) (PacketUtil.KEEPALIVE_INTERVAL * 2.5 * 1000));

    DataInputStream inputStream = new DataInputStream(socket.getInputStream());
    DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());

    // Establish shared secret.
    byte[] sharedSecret = getSharedSecret(inputStream, outputStream);
    logger.info(String.format("Agreed on shared key %s (%d bits)", new BigInteger(sharedSecret).toString(16), sharedSecret.length * Byte.SIZE));

    Remote remote = new Remote(socket, inputStream, outputStream, sharedSecret);

    // Send our identity.
    SecureStorage.INSTANCE.encodeIdentity(getIdentity(), remote);

    // Await their identity.
    // Note that unlike getting shared secret, no handshaking is required.
    // Identity can be sent first and received second on both ends.
    Identity remoteIdentity = SecureStorage.INSTANCE.decodeIdentity(remote, logger);
    remote.setIdentity(remoteIdentity);

    currentClient.set(remote);

    while (!socket.isClosed() && socket.isConnected() && !Thread.interrupted()) {
      if (!remote.readMessage(logger, msg -> listener.accept(remote, msg))) {
        break;
      }
    }
  }

  /**
   * Establish a shared secret.
   *
   * @param inputStream the remote input stream
   * @param outputStream the remote output stream
   * @return the shared secret
   * @throws GeneralSecurityException if a handshaking issue occurs
   * @throws IOException if a communication issue occurs
   */
  protected abstract byte[] getSharedSecret(
      @NotNull DataInputStream inputStream,
      @NotNull DataOutputStream outputStream
  ) throws GeneralSecurityException, IOException;

  public @Nullable Remote getRemote() {
    return this.currentClient.get();
  }

  @Override
  public void close() {
    Thread thread = this.connectionThread.get();
    // Already shut down?
    if (thread == null) {
      return;
    }

    logger.info("Shutting down...");

    // Interrupt thread.
    thread.interrupt();

    Remote remote = currentClient.get();
    if (remote != null) {
      try {
        remote.disconnect();
      } catch (IOException e) {
        logger.warning(() -> "Caught exception disconnecting remote: " + e.getMessage());
        logger.log(Level.FINE, "Exception disconnecting remote", e);
      }
    }

    int shutdownTimeout = 10;
    try {
      // Wait for thread to actually die.
      thread.join(TimeUnit.SECONDS.toMillis(shutdownTimeout));
    } catch (InterruptedException ignored) {
      // Current thread interrupted while waiting for server thread. A comedy of errors.
    }

    // If thread is alive, complain. Otherwise, all done!
    if (thread.isAlive()) {
      logger.warning(() -> String.format("Thread failed to shut down after %d seconds!", shutdownTimeout));
    }
  }

  protected void logPubKey(String identifier, PublicKey key) {
    logger.fine(() -> {
      if (!(key instanceof DHPublicKey dhPub)) {
        return String.format("%s is a %s, not a DHPublicKey!", identifier, key.getClass().getName());
      }
      DHParameterSpec params = dhPub.getParams();
      return String.format(
          "%s: prime=%s, generator=%s, public=%s",
          identifier, params.getP(), params.getG(), dhPub.getY()
      );
    });
  }

}
