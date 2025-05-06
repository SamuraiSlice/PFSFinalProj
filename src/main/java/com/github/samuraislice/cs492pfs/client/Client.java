package com.github.samuraislice.cs492pfs.client;

import com.github.samuraislice.cs492pfs.client.command.Command;
import com.github.samuraislice.cs492pfs.client.command.CommandManager;
import com.github.samuraislice.cs492pfs.common.Remote;
import com.github.samuraislice.cs492pfs.common.SecureStorage;
import com.github.samuraislice.cs492pfs.server.ServerConnection;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Scanner;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Range;

/**
 * Main client hosting connections to and from external servers.
 */
public class Client implements AutoCloseable {

  private static final Logger LOGGER = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

  private final CommandManager manager = new CommandManager("/");
  private final int port;
  private Scanner scanner;
  private ServerConnection server;
  private ClientConnection client;

  public Client(@Range(from = 0, to = 65535) int port) {
    this.port = port;
  }

  /**
   * Open the client. Starts login procedure and handles user interaction.
   */
  public void open() {
    scanner = new Scanner(System.in);

    if (!initSecureStorage()) {
      return;
    }

    String name = intakeUsername();

    BiConsumer<Remote, String> handler =
        (client, message) -> System.out.printf("%s says: %s%n", client.getIdentifier(), message);
    this.server = new ServerConnection(name, handler, port);
    this.client = new ClientConnection(name, handler);

    server.open();

    while (processLine(scanner.nextLine())) {
      // Yep.
    }
  }

  /**
   * Initialize the secure storage.
   *
   * @return true if the secure storage was initialized correctly.
   */
  private boolean initSecureStorage() {
    if (SecureStorage.INSTANCE.exists()) {
      System.out.print("Please enter password: ");
    } else {
      // A more robust system would use a UI and confirmation, but hey.
      System.out.println("Welcome to PfsClient. Please select a password.");
      System.out.println("Your local data is only as safe as your password is good!");
      System.out.print("Password: ");
    }
    try {
      // TODO to hide password, have to convert all usages to use Console.
      //  Even then, gets messy on Windows.
      while (!SecureStorage.INSTANCE.init(scanner.nextLine().toCharArray())) {
        System.out.print("Invalid password. Please enter password: ");
      }
    } catch (GeneralSecurityException | IOException e) {
      LOGGER.severe("Unable to initialize secure storage!");
      LOGGER.log(Level.SEVERE, "Error initializing secure storage", e);
      return false;
    }
    return true;
  }

  /**
   * Intake a username.
   *
   * @return the username
   */
  private @NotNull String intakeUsername() {
    String name;

    do {
      System.out.println("Please select a username. Note that if you change usernames,");
      System.out.println("anyone you connect with will have to re-verify your identity!");
      System.out.print("Username: ");
      name = scanner.next();
      scanner.nextLine();
    } while (name.isBlank());

    return name;
  }

  /**
   * Main client loop. Processes a line of user input.
   *
   * @param input the user input
   * @return true if the client should not close as a result of the input
   */
  private boolean processLine(@NotNull String input) {
    if (input.isBlank()) {
      return true;
    }

    // If the input is a command, handle it.
    if (input.startsWith(manager.getCommandPrefix())) {
      String[] params = input.split(" ");

      // Hardcoded exit command (so that it can't be overridden by accident).
      if ("/exit".equals(params[0])) {
        LOGGER.info("Exiting.");
        return false;
      }

      // Get executed command.
      Command command = manager.getCommand(params[0]);
      if (command != null) {
        // Perform command and send feedback.
        String feedback = command.execute(server, client, params);
        System.out.println(feedback);
      } else {
        LOGGER.warning(() -> String.format("Invalid command \"%s\"", params[0]));
      }
      return true;
    }

    // Otherwise, send chats to connected remotes.
    Remote remote = server.getRemote();
    if (remote == null) {
      remote = client.getRemote();
    }
    // Warn about no remote.
    if (remote == null) {
      LOGGER.warning("Not connected. Try /connect <identifier> <hostname> <port>");
      return true;
    }

    // Send message.
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
    if (client != null) {
      client.close();
    }
    if (server != null) {
      scanner.close();
    }
  }

}
