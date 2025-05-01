package com.github.samuraislice.cs492pfs;

import com.github.samuraislice.cs492pfs.client.Client;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.StreamHandler;

public class Launcher {

  // Parent logger for other project loggers.
  private static final Logger ROOT_LOGGER = Logger.getLogger(Launcher.class.getPackageName());

  static {
    // Configure root logger.
    configureLogger();
  }

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

    try (Client client = new Client(port)) {
      client.open();
    }

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

  private static void configureLogger() {
    Launcher.ROOT_LOGGER.setUseParentHandlers(false);

    Formatter formatter = new Formatter() {
      @Override
      public String format(LogRecord record) {
        String loggerName = record.getLoggerName();
        if (loggerName != null) {
          int lastSeparator = loggerName.lastIndexOf('.');
          if (lastSeparator >= 0) {
            loggerName = loggerName.substring(lastSeparator + 1);
          }
        }
        return String.format(
            "[%1$tF %1$tT] [%2$s] [%3$s] %4$s%n",
            new Date(record.getMillis()), record.getLevel(), loggerName, record.getMessage());
      }
    };

    Launcher.ROOT_LOGGER.addHandler(new StreamHandler(System.out, formatter) {
      @Override
      public void publish(LogRecord record) {
        super.publish(record);
        flush();
      }
    });
  }

}
