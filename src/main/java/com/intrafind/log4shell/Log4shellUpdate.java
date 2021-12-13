package com.intrafind.log4shell;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Log4shellUpdate {

  private static final Pattern VERSION_PATTERN = Pattern.compile("-2\\.(\\d+)\\.\\d+\\.jar");
  private static Map<String, String> replacements;

  static {
    try {
      initReplacementMap();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }
  static final Map<Path, String> TO_REPLACE = new HashMap<>();

  public static void main(String[] args) throws IOException {
    CommandLine cmd = parseCmd(args);
    String path = cmd.getOptionValue("path");

    Files.walk(Paths.get(path))
        .forEach(Log4shellUpdate::addToReplaceIfOldLog4j);
    if (cmd.hasOption("dry-run")) {
      TO_REPLACE.forEach((oldFile, replacement) -> System.out.println("Would replace " + oldFile + " with " + replacement));
    } else {
      TO_REPLACE.forEach((oldFile, replacement) -> {
        try {
          Files.delete(oldFile);
        } catch (IOException e) {
          System.err.println("Could not delete " + path + "! Make sure you have write permissions and the file is not in use. Then restart the utility.");
          throw new IllegalStateException(e);
        }
        final Path pathReplacement = oldFile.getParent().resolve(replacement);
        exportResource(replacement, pathReplacement);
        System.out.println("Replaced " + oldFile + " with " + replacement);
      });
    }
  }


  private static Optional<String> getReplacementIfOld(Path path) {
    final Matcher matcher = VERSION_PATTERN.matcher(path.getFileName().toString());
    if (matcher.find()) {
      if (Integer.parseInt(matcher.group(1)) < 15) {
        return replacements.entrySet().stream()
            .filter(entry -> path.getFileName().toString().startsWith(entry.getKey()))
            .map(Map.Entry::getValue)
            .findFirst();
      }
    }
      return Optional.empty();
  }

  private static void initReplacementMap() throws IOException {
    replacements = new HashMap<>();
    replacements.put("log4j-1.2-api-", "log4j-1.2-api-2.15.0.jar");
    replacements.put("log4j-api-", "log4j-api-2.15.0.jar");
    replacements.put("log4j-core-", "log4j-core-2.15.0.jar");
    replacements.put("log4j-jcl-", "log4j-jcl-2.15.0.jar");
    replacements.put("log4j-layout-template-json-", "log4j-layout-template-json-2.15.0.jar");
    replacements.put("log4j-slf4j-impl-", "log4j-slf4j-impl-2.15.0.jar");
  }


  private static void addToReplaceIfOldLog4j(Path path) {
    if (path.toFile().isDirectory()) {
      return;
    }

    Optional<String> replacement = getReplacementIfOld(path);
    if (!replacement.isPresent()) {
      return;
    }

    final String replacementResource = replacement.get();
    TO_REPLACE.put(path, replacementResource);
  }


  private static CommandLine parseCmd(String[] args) {
    Options options = new Options();
    options.addRequiredOption("p", "path", true, "path to iFinder service");
    options.addOption("d", "dry-run", false, "only print replacements, do not replace files");
    options.addOption("h", "help", false, "print this help");
    CommandLineParser parser = new DefaultParser();

    CommandLine cmd;
    try {
      cmd = parser.parse(options, args);
      if (cmd.hasOption("help")) {
        new HelpFormatter().printHelp("if-log4shell-updater", options);
        System.exit(0);
      }
    } catch (ParseException e) {
      System.err.println(e.getMessage());
      new HelpFormatter().printHelp("if-log4shell-updater", options);
      System.exit(1);
      return null;
    }
    return cmd;
  }


  private static void exportResource(String resourceName, Path exportPath) {
    try {
      OutputStream resStreamOut = null;
      try (InputStream stream = Log4shellUpdate.class.getResourceAsStream("/" + resourceName)) {
        if (stream == null) {
          throw new IllegalStateException("Cannot get resource \"" + resourceName + "\" from Jar file.");
        }

        int readBytes;
        byte[] buffer = new byte[4096];
        final File exportFile = exportPath.toFile();
        if (exportFile.exists()) {
          System.out.println("Replacement " + exportPath + " already exists. Nothing to do.");
        }
        Files.createFile(exportPath);
        resStreamOut = new FileOutputStream(exportFile);
        while ((readBytes = stream.read(buffer)) > 0) {
          resStreamOut.write(buffer, 0, readBytes);
        }
      } finally {
        if (resStreamOut != null) {
          resStreamOut.close();
        }
      }
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }
}
