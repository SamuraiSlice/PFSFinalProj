package com.github.samuraislice.cs492pfs.client;

import com.github.samuraislice.cs492pfs.common.Connection;
import com.github.samuraislice.cs492pfs.common.CryptoConstants;
import com.github.samuraislice.cs492pfs.common.PacketUtil;
import com.github.samuraislice.cs492pfs.common.Remote;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import javax.crypto.KeyAgreement;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Range;

public class ClientConnection extends Connection {

  private @Nullable InetAddress address;
  private int port;

  public ClientConnection(
      @NotNull String identity,
      @NotNull BiConsumer<@NotNull Remote, @NotNull String> listener
  ) {
    super(identity, listener);
  }

  public void setRemote(
      @NotNull InetAddress address,
      @Range(from = 0, to = 65535) int port
  ) {
    this.address = address;
    this.port = port;
  }

  @Override
  public void open() {
    if (address == null) {
      throw new IllegalStateException("Must set remote to connect!");
    }
    if (connectionThread.compareAndSet(null, new ClientThread())) {
      connectionThread.get().start();
    }
  }

  @Override
  public void close() {
    super.close();
    this.address = null;
  }

  @Override
  protected byte[] getSharedSecret(
      @NotNull DataInputStream inputStream,
      @NotNull DataOutputStream outputStream
  ) throws GeneralSecurityException, IOException {

    logger.fine("Generating keypair...");
    // Generate keypair.
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.SHARED_KEY_AGREEMENT);
    keyGen.initialize(CryptoConstants.SHARED_PUB_BITS);
    KeyPair keyPair = keyGen.generateKeyPair();

    PublicKey clientKey = keyPair.getPublic();
    logPubKey("Our key", clientKey);

    // Send server prime, generator, and public key.
    PacketUtil.sendPacket(outputStream, clientKey.getEncoded());

    byte[] serverKeyData = PacketUtil.readPacket(inputStream, logger);
    KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.SHARED_KEY_AGREEMENT);
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverKeyData);
    PublicKey serverKey = keyFactory.generatePublic(keySpec);
    logPubKey("Their key", serverKey);

    // Initialize key agreement.
    KeyAgreement agreement = KeyAgreement.getInstance(CryptoConstants.SHARED_KEY_AGREEMENT);
    agreement.init(keyPair.getPrivate());
    agreement.doPhase(serverKey, true);

    return agreement.generateSecret();
  }

  private class ClientThread extends Thread {

    ClientThread() {
      super("PfsClient");
    }

    @Override
    public void run() {
      try (Socket socket = new Socket(address, port)) {
        handleConnection(socket);
      } catch (EOFException ignored) {
        // Normal disconnection.
        logDisconnect();
      } catch (SocketException e) {
        logDisconnect();
        // "Connection reset" occurs when interrupting.
        if (!"Connection reset".equals(e.getMessage())) {
          logConnectionFailure(e);
        }
      } catch (GeneralSecurityException | IOException e) {
        logConnectionFailure(e);
      }
      currentClient.set(null);
      connectionThread.set(null);
      close();
    }

    private void logDisconnect() {
      Remote connected = currentClient.get();
      if (connected == null) {
        logger.info(() -> String.format("Disconnected from %s:%s", address, port));
      } else {
        logger.info(() -> "Disconnected from " + connected.getIdentifier());
      }
    }

    private void logConnectionFailure(Exception e) {
      logger.info(() -> "Connection lost: " + e.getMessage());
      logger.log(Level.FINE, "Connection failure", e);
    }
  }

}
