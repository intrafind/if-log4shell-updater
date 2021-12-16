package com.intrafind.log4shell;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

@SuppressWarnings("ArraysAsListWithZeroOrOneArgument")
public class Log4shellUpdate {

  private static final Pattern VERSION_PATTERN = Pattern.compile("-2\\.(\\d+)\\.\\d+\\.jar(\\.bak_log4shell)*");
  private static final Pattern DELETE_PATTERN = Pattern.compile("elasticsearch-sql-cli-\\d+\\.\\d+\\.\\d+\\.jar");
  private static final Map<String, String> REPLACEMENTS;
  private static final List<String> VULNERABLE_CLASSES = Arrays.asList("org/apache/logging/log4j/core/lookup/JndiLookup.class");
  private static final Field ZIP_NAMES_FIELD;

  static {
    REPLACEMENTS = new HashMap<>();
    REPLACEMENTS.put("log4j-1.2-api-", "log4j-1.2-api-2.16.0.jar");
    REPLACEMENTS.put("log4j-api-", "log4j-api-2.16.0.jar");
    REPLACEMENTS.put("log4j-core-", "log4j-core-2.16.0.jar");
    REPLACEMENTS.put("log4j-jcl-", "log4j-jcl-2.16.0.jar");
    REPLACEMENTS.put("log4j-layout-template-json-", "log4j-layout-template-json-2.16.0.jar");
    REPLACEMENTS.put("log4j-slf4j-impl-", "log4j-slf4j-impl-2.16.0.jar");

    try {
      ZIP_NAMES_FIELD = ZipOutputStream.class.getDeclaredField("names");
    } catch (NoSuchFieldException e) {
      throw new IllegalStateException(e);
    }
  }

  public static void main(String[] args) throws IOException {
    final CommandLine cmd = parseCmd(args);
    final Path pathOpt = Paths.get(cmd.getOptionValue("path"));

    final Map<Path, String> toReplace = new HashMap<>();
    final List<Path> toDelete = new ArrayList<>();
    final List<Path> fatJars = new ArrayList<>();
    Files.walk(pathOpt).forEach(path -> Log4shellUpdate.handleIfOldLog4j(path, toReplace, toDelete, fatJars));
    if (cmd.hasOption("dry-run")) {
      toReplace.forEach((oldFile, replacement) -> System.out.println("Would replace " + oldFile + " with " + replacement));
      toDelete.forEach(oldFile -> System.out.println("Would delete " + oldFile));
      fatJars.forEach(jar -> System.out.println("Would remove vulnerable classes from " + jar));
    } else {
      toReplace.forEach((oldFile, replacement) -> Log4shellUpdate.checkFilePermissions(oldFile));
      toDelete.forEach(Log4shellUpdate::checkFilePermissions);
      List<Path> backups = new ArrayList<>();
      toReplace.forEach((oldPath, replacement) -> Log4shellUpdate.replace(oldPath, replacement, backups));
      toDelete.forEach(oldPath -> Log4shellUpdate.delete(oldPath, backups));
      if (cmd.hasOption("allow-duplicates")) {
        ZIP_NAMES_FIELD.setAccessible(true);
        fatJars.forEach(fatJar -> Log4shellUpdate.clean(fatJar, backups, true));
      } else {
        fatJars.forEach(fatJar -> Log4shellUpdate.clean(fatJar, backups, false));
      }
      if (cmd.hasOption("delete-backups")) {
        deleteBackups(pathOpt, backups);
      }
    }
  }

  private static CommandLine parseCmd(String[] args) {
    Options options = new Options();
    options.addRequiredOption("p", "path", true, "path to iFinder service");
    options.addOption("d", "dry-run", false, "only print replacements, do not replace files");
    options.addOption("h", "help", false, "print this help");
    options.addOption("b", "delete-backups", false, "delete backups automatically");
    options.addOption("a", "allow-duplicates", false, "allow duplicate entries in zip files (will use reflection)");
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

  private static void handleIfOldLog4j(Path path, Map<Path, String> toReplace, List<Path> toDelete, List<Path> fatJars) {
    if (!path.toFile().isDirectory()) {
      final String filename = path.getFileName().toString();
      if (DELETE_PATTERN.asPredicate().test(filename)) {
        toDelete.add(path);
      } else {
        final Matcher matcher = VERSION_PATTERN.matcher(filename);
        if (matcher.find()) {
          if (Integer.parseInt(matcher.group(1)) < 16) {
            REPLACEMENTS.entrySet().stream()
                .filter(entry -> filename.startsWith(entry.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .ifPresent(replacementResource -> toReplace.put(path, replacementResource));
          }
        }
        if (filename.matches(".*\\.jar") && REPLACEMENTS.keySet().stream().noneMatch(filename::startsWith)) {
          try {
            try (final InputStream fileInputStream = Files.newInputStream(path);
                 final BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream)) {
              if (zipContainsLog4j(bufferedInputStream)) {
                fatJars.add(path);
              }
            }
          } catch (Exception e) {
            System.err.println("Could not analyze " + path + " due to " + e.getMessage());
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
    } catch (Exception e) {
      System.err.println("Unable to delete " + oldFile + "! Make sure you have write permissions and the file is not in use. Then restart the utility.");
      System.exit(1);
    }
  }

  private static void replace(Path oldFile, String replacement, List<Path> backups) {
    delete(oldFile, backups);
    final Path pathReplacement = oldFile.getParent().resolve(replacement);
    try {
      exportResource(replacement, pathReplacement);
    } catch (Exception e) {
      System.err.println("Could not write to " + pathReplacement + " restoring changes...");
      restore(backups);
    }
    System.out.println("Replaced " + oldFile + " with " + replacement);
  }

  private static Path delete(Path oldFile, List<Path> backups) {
    try {
      final Path backupPath = Paths.get(oldFile + ".bak_log4shell");
      Files.move(oldFile, backupPath);
      backups.add(backupPath);
      System.out.println("Backed up " + oldFile);
      return backupPath;
    } catch (Exception e) {
      System.err.println("Could not move " + oldFile + "! Make sure you have write permissions and the file is not in use. Restoring changes...");
      restore(backups);
      System.exit(1);
      return null;
    }
  }

  private static void clean(Path fatJar, List<Path> backups, boolean allowDuplicates) {
    final Path backupPath = delete(fatJar, backups);
    try (final InputStream fileInputStream = Files.newInputStream(backupPath);
         final BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
         final OutputStream fileOutputStream = Files.newOutputStream(fatJar);
         final BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream)) {
      copyZipWithoutVulnerableClasses(bufferedInputStream, bufferedOutputStream, allowDuplicates);
    } catch (Exception e) {
      System.err.println("Could not remove vulnerable classes from " + fatJar + ". Restoring changes...");
      if (e instanceof ZipException && e.getMessage().contains("duplicate entry:")) {
        System.err.println("Please try again with the 'allow-duplicates' option activated. This might cause warnings about illegal reflection occuring. Those may be ignored.");
      }
      try {
        Files.delete(fatJar);
      } catch (IOException ex) {
        System.err.println("Failed to delete incomplete " + fatJar);
      }
      restore(backups);
      System.exit(1);
    }
  }

  private static boolean zipContainsLog4j(InputStream inputStream) throws IOException {
    final ZipInputStream zipInputStream = new ZipInputStream(inputStream);
    for (ZipEntry entry = zipInputStream.getNextEntry(); entry != null; entry = zipInputStream.getNextEntry()) {
      if (VULNERABLE_CLASSES.contains(entry.getName())) {
        return true;
      }
      if (entry.getName().endsWith(".jar")) {
        if (zipContainsLog4j(zipInputStream)) {
          return true;
        }
      }
    }
    return false;
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

  @SuppressWarnings("unchecked")
  private static void copyZipWithoutVulnerableClasses(InputStream inputStream, OutputStream outputStream, boolean allowDuplicates) throws IOException, IllegalAccessException {
    final ZipInputStream zipInputStream = new ZipInputStream(inputStream);
    final ZipOutputStream zipOutputStream = new ZipOutputStream((outputStream));
    for (ZipEntry entry = zipInputStream.getNextEntry(); entry != null; entry = zipInputStream.getNextEntry()) {
      if (VULNERABLE_CLASSES.contains(entry.getName())) {
        continue;
      }
      if (allowDuplicates) {
        ((Set<String>) ZIP_NAMES_FIELD.get(zipOutputStream)).clear();
      }
      zipOutputStream.putNextEntry(new ZipEntry(entry.getName()));
      if (entry.getName().endsWith(".jar")) {
        copyZipWithoutVulnerableClasses(zipInputStream, zipOutputStream, allowDuplicates);
      } else {
        copyStream(zipInputStream, zipOutputStream);
      }
      zipOutputStream.closeEntry();
    }
    zipOutputStream.finish();
  }

  private static void copyStream(InputStream inputStream, OutputStream outputStream) throws IOException {
    byte[] buffer = new byte[4096];
    int length;
    while ((length = inputStream.read(buffer)) != -1) {
      outputStream.write(buffer, 0, length);
    }
  }

  private static void restore(List<Path> backups) {
    for (Path backup : backups) {
      final Path restorePath = Paths.get(backup.toString().replaceAll("(\\.bak_log4shell)+$", ""));
      try {
        Files.move(backup, restorePath);
      } catch (Exception e) {
        System.err.println("Restoring " + backup + " failed!");
        e.printStackTrace();
      }
    }
  }

  private static void deleteBackups(Path dir, List<Path> backups) throws IOException {
    for (Path backup : backups) {
      deleteBackup(backup);
    }
    Files.walk(dir)
        .filter(path -> path.toString().endsWith(".bak_log4shell"))
        .forEach(Log4shellUpdate::deleteBackup);
  }

  private static void deleteBackup(Path backup) {
    try {
      Files.delete(backup);
      System.out.println("Deleted backup " + backup);
    } catch (Exception e) {
      System.err.println("Deleting backup " + backup + " failed!");
      e.printStackTrace();
    }
  }
}
