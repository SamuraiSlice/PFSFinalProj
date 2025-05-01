package com.github.samuraislice.cs492pfs.client;

import com.github.samuraislice.cs492pfs.client.command.Command;
import com.github.samuraislice.cs492pfs.client.command.CommandManager;
import com.github.samuraislice.cs492pfs.common.Remote;
import com.github.samuraislice.cs492pfs.server.ServerConnection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Scanner;
import java.util.function.BiConsumer;

public class Client implements AutoCloseable {

  private final CommandManager manager = new CommandManager("/");
  private final Scanner scanner = new Scanner(System.in);
  private final ServerConnection server;
  private final ClientConnection client;

  public Client(@Range(from = 0, to = 65535) int port) {
    BiConsumer<Remote, String> handler =
        (client, message) -> System.out.printf("%s says: %s%n", client.getIdentifier(), message);
    this.server = new ServerConnection(port, handler);
    this.client = new ClientConnection(handler);
  }

  public void open() {
    // TODO open encrypted keystore(s)

    server.open();

    while (processLine(scanner.nextLine())) {
      // Yep.
    }

  }

  private boolean processLine(@NotNull String input) {
    if (input.isBlank()) {
      return true;
    }

    if (input.startsWith(manager.getCommandPrefix())) {
      String[] params = input.split(" ");
      Command command = manager.getCommand(params[0]);
      if (command != null) {
        String feedback = command.execute(server, client, params);
        System.out.println(feedback);
      } else {
        System.out.printf("Invalid command \"%s\"%n", params[0]);
      }
      return true;
    }

    Remote remote = server.getRemote();
    if (remote == null) {
      remote = client.getRemote();
    }
    if (remote == null) {
      System.out.println("Not connected. Try /connect <identifier> <hostname> <port>");
      return true;
    }

    try {
      remote.sendMessage(input);
    } catch (GeneralSecurityException | IOException e) {
      // TODO better logging
      System.out.println("An exception occurred while sending the message.");
      e.printStackTrace();
    }
    return true;
  }

  @Override
  public void close() {
    server.close();
    client.close();
    scanner.close();
  }

}
