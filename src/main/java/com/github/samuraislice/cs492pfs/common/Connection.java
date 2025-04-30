package com.github.samuraislice.cs492pfs.common;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.logging.Logger;

public abstract class Connection implements AutoCloseable {

  protected final Logger logger;
  protected final AtomicReference<Thread> connectionThread = new AtomicReference<>();
  protected final AtomicReference<Remote> currentClient = new AtomicReference<>();
  private final BiConsumer<@NotNull Remote, @NotNull String> listener;

  protected Connection(
      @NotNull Logger logger,
      @NotNull BiConsumer<@NotNull Remote, @NotNull String> listener) {
    this.logger = logger;
    this.listener = listener;
  }

  public abstract void open();

  protected void handleConnection(@NotNull Socket socket)
      throws GeneralSecurityException, IOException {
    socket.setSoTimeout((int) (PacketUtil.KEEPALIVE_INTERVAL * 2.5));
    socket.setKeepAlive(true); // TODO is this enough?

    DataInputStream inputStream = new DataInputStream(socket.getInputStream());
    DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());

    byte[] sharedSecret = getSharedSecret(inputStream, outputStream);
    logger.fine(String.format("Agreed on shared key %s (%d bits)", new BigInteger(sharedSecret).toString(16), sharedSecret.length * Byte.SIZE));

    // TODO PFS without other stuff is largely useless, no guards against MitM etc.
    //  Post-discussion:
    //  - add some form of public key encryption
    //  - first connect: trust keypair
    //  - store pubkey in encrypted keystore
    //  - subsequent connects: mandate same keypair used (with override)

    SecretKeySpec keySpec = new SecretKeySpec(sharedSecret, "AES");
    // TODO investigate other paddings
    Cipher encoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
    encoder.init(Cipher.ENCRYPT_MODE, keySpec);

    Remote client = new Remote(outputStream, encoder);
    currentClient.set(client);

    Cipher decoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
    decoder.init(Cipher.DECRYPT_MODE, keySpec);

    while (!socket.isClosed() && socket.isConnected() && !Thread.interrupted()) {
      byte[] data = PacketUtil.readPacket(inputStream, logger);
      // TODO quit should be signed.
      if (data.length == 1 && data[0] == -1) {
        listener.accept(client, "Disconnected.");
        break;
      }
      data = decoder.doFinal(data);

      if (data.length > 0) {
        listener.accept(client, new String(data, StandardCharsets.UTF_8));
      }
    }
  }

  protected abstract byte[] getSharedSecret(
      @NotNull DataInputStream inputStream,
      @NotNull DataOutputStream outputStream
  ) throws GeneralSecurityException, IOException;

  public @Nullable Remote getClient() {
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

}
