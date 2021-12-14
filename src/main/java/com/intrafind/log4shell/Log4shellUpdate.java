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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Log4shellUpdate {

  private static final Pattern VERSION_PATTERN = Pattern.compile("-2\\.(\\d+)\\.\\d+\\.jar(\\.bak)*");
  private static final Pattern ES_SQL_CLI_PATTERN = Pattern.compile("elasticsearch-sql-cli-\\d+\\.\\d+\\.\\d+.jar");
  private static final Map<String, String> replacements;

  static {
    replacements = new HashMap<>();
    replacements.put("log4j-1.2-api-", "log4j-1.2-api-2.16.0.jar");
    replacements.put("log4j-api-", "log4j-api-2.16.0.jar");
    replacements.put("log4j-core-", "log4j-core-2.16.0.jar");
    replacements.put("log4j-jcl-", "log4j-jcl-2.16.0.jar");
    replacements.put("log4j-layout-template-json-", "log4j-layout-template-json-2.16.0.jar");
    replacements.put("log4j-slf4j-impl-", "log4j-slf4j-impl-2.16.0.jar");
  }

  public static void main(String[] args) throws IOException {
    CommandLine cmd = parseCmd(args);
    String pathOption = cmd.getOptionValue("path");

    final Map<Path, String> toReplace = new HashMap<>();
    final List<Path> toDelete = new ArrayList<>();
    Files.walk(Paths.get(pathOption))
        .forEach(path -> Log4shellUpdate.handleIfOldLog4j(path, toReplace, toDelete));
    if (cmd.hasOption("dry-run")) {
      toReplace.forEach((oldFile, replacement) -> System.out.println("Would replace " + oldFile + " with " + replacement));
      toDelete.forEach(oldFile -> System.out.println("Would delete " + oldFile));
    } else {
      toReplace.forEach((oldFile, replacement) -> Log4shellUpdate.checkFilePermissions(oldFile));
      toDelete.forEach(Log4shellUpdate::checkFilePermissions);
      List<Path> backups = new ArrayList<>();
      toReplace.forEach((oldPath, replacement) -> Log4shellUpdate.replace(oldPath, replacement, backups));
      toDelete.forEach(oldPath -> Log4shellUpdate.delete(oldPath, backups));
      if (cmd.hasOption("delete-backups")) {
        deleteBackups(backups);
      }
    }
  }

  private static CommandLine parseCmd(String[] args) {
    Options options = new Options();
    options.addRequiredOption("p", "path", true, "path to iFinder service");
    options.addOption("d", "dry-run", false, "only print replacements, do not replace files");
    options.addOption("h", "help", false, "print this help");
    options.addOption("b", "delete-backups", false, "delete backups automatically");
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

  private static void handleIfOldLog4j(Path path, Map<Path, String> toReplace, List<Path> toDelete) {
    if (!path.toFile().isDirectory()) {
      final String filename = path.getFileName().toString();
      if (ES_SQL_CLI_PATTERN.asPredicate().test(filename)) {
        toDelete.add(path);
      } else {
        final Matcher matcher = VERSION_PATTERN.matcher(filename);
        if (matcher.find()) {
          if (Integer.parseInt(matcher.group(1)) < 16) {
            replacements.entrySet().stream()
                .filter(entry -> filename.startsWith(entry.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .ifPresent(replacementResource -> toReplace.put(path, replacementResource));
          }
        }
      }
    }
  }

  private static void checkFilePermissions(Path oldFile) {
    try {
      if (!oldFile.getParent().toFile().canWrite()) {
        System.err.println("Unable to delete " + oldFile + "! Make sure you have write permissions and the file is not in use. Then restart the utility.");
        System.exit(1);
      }
      Files.move(oldFile, oldFile);
    } catch (IOException e) {
      System.err.println("Unable to delete " + oldFile + "! Make sure you have write permissions and the file is not in use. Then restart the utility.");
      System.exit(1);
    }
  }

  private static void replace(Path oldFile, String replacement, List<Path> backups) {
    delete(oldFile, backups);
    final Path pathReplacement = oldFile.getParent().resolve(replacement);
    try {
      exportResource(replacement, pathReplacement);
    } catch (IOException e) {
      System.err.println("Could not write to " + pathReplacement + " restoring changes...");
      restore(backups);
    }
    System.out.println("Replaced " + oldFile + " with " + replacement);
  }

  private static void delete(Path oldFile, List<Path> backups) {
    try {
      final Path backupPath = Paths.get(oldFile + ".bak");
      Files.move(oldFile, backupPath);
      backups.add(backupPath);
      System.out.println("Backed up " + oldFile);
    } catch (IOException e) {
      System.err.println("Could not move " + oldFile + "! Make sure you have write permissions and the file is not in use. Restoring changes...");
      restore(backups);
      System.exit(1);
    }
  }

  private static void exportResource(String resourceName, Path exportPath) throws IOException {
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
        return;
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
  }

  private static void restore(List<Path> backups) {
    for (Path backup : backups) {
      final Path restorePath = Paths.get(backup.toString().replaceAll("(\\.bak)+$", ""));
      try {
        Files.move(backup, restorePath);
      } catch (IOException e) {
        System.err.println("Restoring " + backup + " failed!");
        e.printStackTrace();
      }
    }
  }

  private static void deleteBackups(List<Path> backups) {
    for (Path backup : backups) {
      try {
        Files.delete(backup);
      } catch (IOException e) {
        System.err.println("Deleting backup " + backup + " failed!");
        e.printStackTrace();
      }
    }
  }
}
