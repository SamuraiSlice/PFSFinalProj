package com.github.samuraislice.cs492pfs;

import com.github.samuraislice.cs492pfs.client.Client;
import com.github.samuraislice.cs492pfs.common.Remote;
import com.github.samuraislice.cs492pfs.server.Server;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import java.util.function.BiConsumer;

public class Launcher {

  public static void main(String[] args) {
    // Set up cli options.
    Options options = getOptions();

    // Parse options.
    CommandLineParser parser = new DefaultParser();
    CommandLine line;
    try {
      line = parser.parse(options, args);
    } catch (ParseException e) {
      printHelp(e.getMessage(), options);
      return;
    }

    // Convert strings into usable values.
    String portString = line.getOptionValue("p");
    int port;
    try {
      port = Integer.parseInt(portString);
      // Could possibly also exit here, but we can just sanitize this.
      port = port % 65535;
      if (port < 0) {
        port += 65535;
      }
    } catch (NumberFormatException e) {
      printHelp(e.getMessage(), options);
      return;
    }

    BiConsumer<Remote, String> handler =
        (client, message) -> System.out.printf("%s says: %s\n%n", "TODO", message);
    try (
        Server server = new Server(port, handler);
        Client client = new Client(handler) // TODO client may move to execution of /connect
    ) {
      server.open();
      client.open();
    }

    // TODO intake commands
    //  /connect <remote>
    //  /exit
    //  etc.
    //  Treat non-commands as messages? For single client-client

  }

  private static Options getOptions() {
    // TODO options for disabling server?
    Options options = new Options();

    Option port = new Option("p", "port", true, "numeric internal server port");
    port.setRequired(true);
    options.addOption(port);

    return options;
  }

  private static void printHelp(String message, Options options) {
    System.out.println(message);
    new HelpFormatter().printHelp("java -jar cs492pfs.jar", options);
    System.exit(1);
  }

}
