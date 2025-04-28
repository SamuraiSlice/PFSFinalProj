package com.github.samuraislice.cs492pfs.server;

import com.github.samuraislice.cs492pfs.common.ConnectedClient;
import com.github.samuraislice.cs492pfs.common.PacketUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.Range;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
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
    } else {
      serverThread.set(null);
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
      // TODO netty or similar? Multiple connections?
      //  A future problem.
      logger.info(() -> String.format("Starting server on port %d...", port));
      try (ServerSocket socket = new ServerSocket(port)) {
        while (acceptingConnections.get()) {
          logger.info("Listening for connections.");
          try (Socket client = socket.accept()) {
            logger.info(() -> String.format("Accepted connection from %s", client.getRemoteSocketAddress()));
            handleConnection(client);

            // TODO handle client stuff
          } catch (Exception e) {
            // TODO log handling
            logger.info("Client disconnected!");
            logger.log(Level.INFO, "Client disconnection", e);
          }
        }
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

  }

  private void handleConnection(@NotNull Socket socket) throws IOException {
    DataInputStream inputStream = new DataInputStream(socket.getInputStream());

    byte[] data = PacketUtil.readPacket(inputStream, logger);
    BigInteger prime = new BigInteger(data);
    if (prime.compareTo(BigInteger.ONE) < 1) {
      logger.warning(() -> String.format("Received prime value %s <= 1!", prime));
      return;
    }

    data = PacketUtil.readPacket(inputStream, logger);
    BigInteger generator = new BigInteger(data);
    if (generator.compareTo(BigInteger.ONE) < 1) {
      logger.warning(() -> String.format("Received generator value %s <= 1!", generator));
      return;
    }



    DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());

    // TODO client handling
    //  Send new pubkey
    //  Await messages
    //  Periodic keepalives if no messages
  }

}
