package com.github.samuraislice.cs492pfs.client;

import com.github.samuraislice.cs492pfs.common.ConnectedClient;
import com.github.samuraislice.cs492pfs.server.Server;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

public abstract class Client implements AutoCloseable {

  private final Server server;

  public Client(@Range(from = 0, to = 65535) int port) {
    this.server = new Server(port, this::handleMessage);
  }

  public void start() {
    server.start();
  }

  public void connect(String address, int port) throws UnknownHostException, IOException {
    // TODO need a thread per server connected to
    Socket socket = new Socket(address, port);
    // TODO
    //  send prime
    //  send generator
    //  get server pubkey
    //  establish shared secret
    // when named, do conflict resolution on name
  }

  protected abstract void handleMessage(@NotNull ConnectedClient sender, @NotNull String message);

  @Override
  public void close() {
    server.close();
  }
}
