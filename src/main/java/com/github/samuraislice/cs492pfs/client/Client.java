package com.github.samuraislice.cs492pfs.client;

import com.github.samuraislice.cs492pfs.client.command.Command;
import com.github.samuraislice.cs492pfs.client.command.CommandManager;
import com.github.samuraislice.cs492pfs.common.Remote;
import com.github.samuraislice.cs492pfs.server.ServerConnection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;
import java.util.Scanner;
import java.util.function.BiConsumer;

public class Client implements AutoCloseable {

  private final CommandManager manager = new CommandManager("/");
  private final Scanner scanner = new Scanner(System.in);
  private final ServerConnection server;
  private final ClientConnection client;

  public Client(@Range(from = 0, to = 65535) int port) {
    BiConsumer<Remote, String> handler =
        (client, message) -> System.out.printf("%s says: %s\n%n", "TODO", message);
    this.server = new ServerConnection(port, handler);
    this.client = new ClientConnection(handler);
  }

  public void open() {
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
        command.execute(server, client, params);
      }
    }
    // TODO Treat non-commands as messages for single client-client

    return true;
  }

  @Override
  public void close() {
    server.close();
    client.close();
    scanner.close();
  }

}
