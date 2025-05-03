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
import java.util.logging.Level;
import java.util.logging.Logger;

public class Client implements AutoCloseable {

  private static final Logger LOGGER = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

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

      if ("/exit".equals(params[0])) {
        LOGGER.info("Exiting.");
        return false;
      }

      Command command = manager.getCommand(params[0]);
      if (command != null) {
        String feedback = command.execute(server, client, params);
        System.out.println(feedback);
      } else {
        LOGGER.warning(() -> String.format("Invalid command \"%s\"%n", params[0]));
      }
      return true;
    }

    Remote remote = server.getRemote();
    if (remote == null) {
      remote = client.getRemote();
    }
    if (remote == null) {
      LOGGER.warning("Not connected. Try /connect <identifier> <hostname> <port>");
      return true;
    }

    try {
      remote.sendMessage(input);
    } catch (GeneralSecurityException | IOException e) {
      LOGGER.warning("An exception occurred while sending the message: " + e.getMessage());
      LOGGER.log(Level.FINE, "Message sending exception", e);
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
