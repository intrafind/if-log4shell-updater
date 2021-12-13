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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Log4shellUpdate {

  private static final Pattern VERSION_PATTERN = Pattern.compile("-2\\.(\\d+)\\.\\d+\\.jar");
  private static final Map<String, String> replacements;

  static {
    replacements = new HashMap<>();
    replacements.put("log4j-1.2-api-", "log4j-1.2-api-2.15.0.jar");
    replacements.put("log4j-api-", "log4j-api-2.15.0.jar");
    replacements.put("log4j-core-", "log4j-core-2.15.0.jar");
    replacements.put("log4j-jcl-", "log4j-jcl-2.15.0.jar");
    replacements.put("log4j-layout-template-json-", "log4j-layout-template-json-2.15.0.jar");
    replacements.put("log4j-slf4j-impl-", "log4j-slf4j-impl-2.15.0.jar");
  }

  public static void main(String[] args) throws IOException {
    CommandLine cmd = parseCmd(args);
    String pathOption = cmd.getOptionValue("path");

    final Map<Path, String> toReplace = new HashMap<>();
    Files.walk(Paths.get(pathOption))
        .forEach(path -> Log4shellUpdate.addToReplaceIfOldLog4j(path, toReplace));
    if (cmd.hasOption("dry-run")) {
      toReplace.forEach((oldFile, replacement) -> System.out.println("Would replace " + oldFile + " with " + replacement));
    } else {
      toReplace.forEach(Log4shellUpdate::replace);
    }
  }

  private static CommandLine parseCmd(String[] args) {
    Options options = new Options();
    options.addRequiredOption("p", "path", true, "path to iFinder service");
    options.addOption("d", "dry-run", false, "only print replacements, do not replace files");
    options.addOption("h", "help", false, "print this help");
    CommandLineParser parser = new DefaultParser();

    try {
      CommandLine cmd = parser.parse(options, args);
      if (cmd.hasOption("help")) {
        new HelpFormatter().printHelp("if-log4shell-updater", options);
        System.exit(0);
      }
      return cmd;
    } catch (ParseException e) {
      System.err.println(e.getMessage());
      new HelpFormatter().printHelp("if-log4shell-updater", options);
      System.exit(1);
      return null;
    }
  }

  private static void addToReplaceIfOldLog4j(Path path, Map<Path, String> toReplace) {
    if (!path.toFile().isDirectory()) {
      final Matcher matcher = VERSION_PATTERN.matcher(path.getFileName().toString());
      if (matcher.find()) {
        if (Integer.parseInt(matcher.group(1)) < 15) {
          replacements.entrySet().stream()
              .filter(entry -> path.getFileName().toString().startsWith(entry.getKey()))
              .map(Map.Entry::getValue)
              .findFirst()
              .ifPresent(replacementResource -> toReplace.put(path, replacementResource));
        }
      }
    }
  }

  private static void replace(Path oldFile, String replacement) {
    try {
      Files.delete(oldFile);
    } catch (IOException e) {
      System.err.println("Could not delete " + oldFile + "! Make sure you have write permissions and the file is not in use. Then restart the utility.");
      System.exit(1);
    }
    final Path pathReplacement = oldFile.getParent().resolve(replacement);
    exportResource(replacement, pathReplacement);
    System.out.println("Replaced " + oldFile + " with " + replacement);
  }

  private static void exportResource(String resourceName, Path exportPath) {
    try {
      OutputStream targetFile = null;
      try (InputStream resourceStream = Log4shellUpdate.class.getResourceAsStream("/" + resourceName)) {
        if (resourceStream == null) {
          throw new IllegalStateException("Cannot get resource \"" + resourceName + "\" from Jar file.");
        }

        int readBytes;
        byte[] buffer = new byte[4096];
        final File exportFile = exportPath.toFile();
        if (exportFile.exists()) {
          System.out.println("Replacement " + exportPath + " already exists. Nothing to do.");
        }
        Files.createFile(exportPath);
        targetFile = new FileOutputStream(exportFile);
        while ((readBytes = resourceStream.read(buffer)) > 0) {
          targetFile.write(buffer, 0, readBytes);
        }
      } finally {
        if (targetFile != null) {
          targetFile.close();
        }
      }
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }
}
