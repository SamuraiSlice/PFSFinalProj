package com.github.samuraislice.cs492pfs.client.command;

import com.github.samuraislice.cs492pfs.client.ClientConnection;
import com.github.samuraislice.cs492pfs.common.Remote;
import com.github.samuraislice.cs492pfs.server.ServerConnection;
import org.jetbrains.annotations.NotNull;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class CommandConnect extends Command {

  @Override
  public String execute(
      @NotNull ServerConnection server,
      @NotNull ClientConnection client,
      String @NotNull ... args
  ) {
    if (args.length < 4) {
      return "Usage: /connect <identifier> <host> <port>";
    }

    // Handle existing server connection.
    if (false && server.isAcceptingConnections()) { // TODO temp flag to leave server connectable (connect to self)
      Remote remote = server.getRemote();
      if (remote != null) {
        return alreadyConnected(remote);
      }
      // TODO log why server is closing
      server.close();
    }

    // Handle existing client connection.
    Remote remote = client.getRemote();
    if (remote != null) {
      return alreadyConnected(remote);
    }

    // Just in case, close client.
    client.close();

    // Convert hostname to address.
    InetAddress address;
    try {
      address = InetAddress.getByName(args[2]);
    } catch (UnknownHostException e) {
      // TODO log error
      return "Unknown host " + args[2];
    }

    // Parse port.
    int port;
    try {
      port = Integer.parseInt(args[3]);
    } catch (NumberFormatException e) {
      return "Invalid port number " + args[3];
    }
    if (port < 0 || port > 65535) {
      return "Invalid port (range 0-65535)";
    }

    client.setRemote(args[1], address, port);
    client.open();

    return "Initiating connection...";
  }

  private String alreadyConnected(@NotNull Remote remote) {
    return String.format(
        "You are already connected to %s. Please /disconnect first.",
        remote.getIdentifier()
    );
  }

}
