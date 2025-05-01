package com.github.samuraislice.cs492pfs.client;

import com.github.samuraislice.cs492pfs.common.Remote;
import com.github.samuraislice.cs492pfs.common.Connection;
import com.github.samuraislice.cs492pfs.common.PacketUtil;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.BiConsumer;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Range;

public class ClientConnection extends Connection {

  private @Nullable InetAddress address;
  private int port;

  public ClientConnection(@NotNull BiConsumer<@NotNull Remote, @NotNull String> listener) {
    super(listener);
  }

  public void setRemote(
      @NotNull String name, // TODO send to server
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
    if (!connectionThread.compareAndSet(null, new ClientThread())) {
      // If the client thread is running already, deny.
      throw new IllegalStateException("ClientConnection is already connected!");
    } else {
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
    // Generate 2048-bit keypair.
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();

    PublicKey clientKey = keyPair.getPublic();
    logPubKey("Our key", clientKey);

    // Send server prime, generator, and public key.
    PacketUtil.sendPacket(outputStream, clientKey.getEncoded());

    byte[] serverKeyData = PacketUtil.readPacket(inputStream, logger);
    KeyFactory keyFactory = KeyFactory.getInstance("DH");
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverKeyData);
    PublicKey serverKey = keyFactory.generatePublic(keySpec);
    logPubKey("Their key", serverKey);

    // Initialize key agreement.
    KeyAgreement agreement = KeyAgreement.getInstance("DH");
    agreement.init(keyPair.getPrivate());
    agreement.doPhase(serverKey, true);

    return agreement.generateSecret();
  }

  private void logPubKey(String identifier, PublicKey key) {
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

  private class ClientThread extends Thread {
    @Override
    public void run() {
      try (Socket socket = new Socket(address, port)) {
        handleConnection(socket);
        currentClient.set(null);
      } catch (EOFException ignored) {
        // Disconnection.
      } catch (GeneralSecurityException | IOException e) {
        connectionThread.set(null);
        throw new RuntimeException(e);
      }
      connectionThread.set(null);
      close();
    }
  }

}
