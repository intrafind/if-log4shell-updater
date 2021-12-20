package com.intrafind.log4shell;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

@SuppressWarnings("ArraysAsListWithZeroOrOneArgument")
public class Log4shellUpdate {

  static boolean IS_WINDOWS = '\\' == File.separatorChar;

  private static final Pattern VERSION_PATTERN = Pattern.compile("-2\\.(\\d+)\\.\\d+\\.jar(\\.bak_log4shell)*");
  private static final Pattern DELETE_PATTERN = Pattern.compile("elasticsearch-sql-cli-\\d+\\.\\d+\\.\\d+\\.jar");
  private static final Pattern LOG4J1_PATTERN = Pattern.compile("log4j-1.2.\\d+\\.jar");
  private static final Map<String, String> REPLACEMENTS;
  private static final List<String> VULNERABLE_CLASSES = Arrays.asList("org/apache/logging/log4j/core/lookup/JndiLookup.class");
  private static final Field ZIP_NAMES_FIELD;
  static final String LOG4J2_WRAPPER_SETTINGS =
      "\n" +
      "#use the BasicContextSelector for Log4j2 as recommended for standalone applications\n" +
      "#see https://logging.apache.org/log4j/2.x/manual/logsep.html\n" +
      "wrapper.java.additional.log4jcs = -Dlog4j2.contextSelector=org.apache.logging.log4j.core.selector.BasicContextSelector\n" +
      "#deactivate jmx registration for log4j2 loggers to avoid exceptions\n" +
      "wrapper.java.additional.log4jmx = -Dlog4j2.disableJmx=true\n" +
      "#log4j configuration file\n" +
      "wrapper.java.additional.log4jfile = -Dlog4j2.configurationFile=log4j2.xml\n";
  static final String LOG4J1_CONFIGURATION = "-Dlog4j.configuration=../conf/log4j.properties";
  static final String LOG4J2_CONFIGURATION = "-Dlog4j2.configurationFile=../conf/log4j2.xml";
  private static final String BACKUP_SUFFIX = ".bak_log4shell";

  static {
    REPLACEMENTS = new HashMap<>();
    REPLACEMENTS.put("log4j-1.2-api-", "log4j-1.2-api-2.17.0.jar");
    REPLACEMENTS.put("log4j-api-", "log4j-api-2.17.0.jar");
    REPLACEMENTS.put("log4j-core-", "log4j-core-2.17.0.jar");
    REPLACEMENTS.put("log4j-jcl-", "log4j-jcl-2.17.0.jar");
    REPLACEMENTS.put("log4j-layout-template-json-", "log4j-layout-template-json-2.17.0.jar");
    REPLACEMENTS.put("log4j-slf4j-impl-", "log4j-slf4j-impl-2.17.0.jar");

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
    final List<Path> addedFiles = new ArrayList<>();
    final List<Path> toDelete = new ArrayList<>();
    final Map<Path, String> toAdd = new HashMap<>();
    final Map<Path, String> toAppend = new HashMap<>();
    final Map<Path, Map<String, String>> toReplaceInFile = new HashMap<>();
    final List<Path> fatJars = new ArrayList<>();
    Files.walk(pathOpt).forEach(path -> Log4shellUpdate.handleIfOldLog4j2(path, toReplace, toDelete, fatJars));
    if (cmd.hasOption("replace-log4j1")) {
      Files.walk(pathOpt).forEach(path -> Log4shellUpdate.handleIfLog4j1(path, toDelete, toAdd, toAppend, toReplaceInFile, toReplace));
    }
    if (cmd.hasOption("dry-run")) {
      toReplace.forEach((oldFile, replacement) -> System.out.println("Would replace " + oldFile + " with " + replacement));
      toDelete.forEach(oldFile -> System.out.println("Would delete " + oldFile));
      fatJars.forEach(jar -> System.out.println("Would remove vulnerable classes from " + jar));
      toAdd.forEach((file, content) -> System.out.println("Would create " + file));
      toAppend.forEach((file, content) -> System.out.println("Would append to " + file));
      toReplaceInFile.forEach((file, content) -> System.out.println("Would modify " + file));
    } else {
      toReplace.forEach((oldFile, replacement) -> Log4shellUpdate.checkFilePermissions(oldFile));
      toDelete.forEach(Log4shellUpdate::checkFilePermissions);
      toAppend.forEach((file, content) -> Log4shellUpdate.checkFilePermissions(file));
      toReplaceInFile.forEach((file, content) -> Log4shellUpdate.checkFilePermissions(file));
      List<Path> backups = new ArrayList<>();
      toReplace.forEach((oldPath, replacement) -> Log4shellUpdate.replace(oldPath, replacement, backups, addedFiles));
      toDelete.forEach(oldPath -> Log4shellUpdate.delete(oldPath, backups, addedFiles));
      if (cmd.hasOption("allow-duplicates")) {
        ZIP_NAMES_FIELD.setAccessible(true);
        fatJars.forEach(fatJar -> Log4shellUpdate.clean(fatJar, backups, addedFiles, true));
      } else {
        fatJars.forEach(fatJar -> Log4shellUpdate.clean(fatJar, backups, addedFiles, false));
      }
      toAdd.forEach((file, content) -> addFile(file, content, backups, addedFiles));
      toAppend.forEach((file, content) -> appendToFile(file, content, backups, addedFiles));
      toReplaceInFile.forEach((file, replacements) -> replaceInFile(file, replacements, backups, addedFiles));
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
    options.addOption("l1", "replace-log4j1", false, "replace logg4j1 with current log4j2 libraries");
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

  private static void handleIfOldLog4j2(Path path, Map<Path, String> toReplace, List<Path> toDelete, List<Path> fatJars) {
    if (!path.toFile().isDirectory()) {
      final String filename = path.getFileName().toString();
      if (DELETE_PATTERN.asPredicate().test(filename)) {
        toDelete.add(path);
      } else {
        final Matcher matcher = VERSION_PATTERN.matcher(filename);
        if (matcher.find()) {
          if (Integer.parseInt(matcher.group(1)) < 17) {
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

  @SuppressWarnings("ConstantConditions")
  private static void handleIfLog4j1(Path path, List<Path> toDelete, Map<Path, String> toAdd, Map<Path, String> toAppend, Map<Path, Map<String, String>> toReplaceInFile, Map<Path, String> toReplace) {
    if (LOG4J1_PATTERN.asPredicate().test(path.getFileName().toString())) {
      final Path basePath = path.getParent().getParent();
      final Path[] slf4jImpls;
      try {
        slf4jImpls = Files.list(basePath.resolve("lib")).filter(file -> file.getFileName().toString().matches("slf4j-log4j12-.*\\.jar")).toArray(Path[]::new);
      } catch (IOException e) {
        System.err.println("Could not determine SLF4J implementation for " + basePath + ". Cannot replace " + path + " Exception: " + e.getMessage());
        return;
      }
      if (slf4jImpls.length > 1) {
        System.err.println("Could not determine SLF4J implementation for " + basePath + ". Cannot replace " + path);
        return;
      } else if (slf4jImpls.length == 1) {
        toReplace.put(basePath.resolve("lib").resolve(slf4jImpls[0]), "log4j-slf4j-impl-2.16.0.jar");
      }
      if (isIntrafindService(path)) {
        toDelete.add(basePath.resolve("log4j.properties"));
        toAdd.put(basePath.resolve("log4j2.xml"), "log4j2.xml");
        toAppend.put(basePath.resolve("conf/wrapper.conf"), LOG4J2_WRAPPER_SETTINGS);
      } else if (isIntrafindWebapp(path)) {
        toDelete.add(basePath.resolve("classes/log4j.properties"));
        toAdd.put(basePath.resolve("classes/log4j2.xml"), "log4j2.xml");
      } else if (isIntrafindApp(path)) {
        String[] startScripts = basePath.resolve(IS_WINDOWS ? "bat" : "bin").toFile().list((dir, name) -> name.startsWith("start_"));
        if (startScripts.length != 1) {
          System.err.println("Could not determine start script for " + basePath + ". Cannot replace " + path);
          return;
        }
        final Path startScriptPath = basePath.resolve((IS_WINDOWS ? "bat/" : "bin/") + startScripts[0]);
        try (InputStream startScript = Files.newInputStream(startScriptPath);
             InputStreamReader reader = new InputStreamReader(startScript);
             BufferedReader bufferedReader = new BufferedReader(reader)) {
          if (bufferedReader.lines().noneMatch(line -> line.contains(LOG4J1_CONFIGURATION))) {
            System.err.println("Cannot replace " + path + " as the start script " + startScriptPath + " is not well formatted.");
            return;
          }
        } catch (FileNotFoundException e) {
          System.err.println("Cannot replace " + path + " as the start script " + startScriptPath + " does not exist.");
        } catch (Exception e) {
          System.err.println("Cannot replace " + path + " due to an error: " + e.getMessage());
        }
        toReplaceInFile.put(startScriptPath, Collections.singletonMap(LOG4J1_CONFIGURATION, LOG4J2_CONFIGURATION));
        toDelete.add(basePath.resolve("conf/log4j.properties"));
        toAdd.put(basePath.resolve("conf/log4j2.xml"), "log4j2.xml");
      } else {
        System.err.println("Cannot replace " + path + " as it is not part of a known IntraFind structure.");
      }
      toDelete.add(path);
      toAdd.put(basePath.resolve("lib/log4j-1.2-api-2.16.0.jar"), "log4j-1.2-api-2.16.0.jar");
      toAdd.put(basePath.resolve("lib/log4j-api-2.16.0.jar"), "log4j-api-2.16.0.jar");
      toAdd.put(basePath.resolve("lib/log4j-core-2.16.0.jar"), "log4j-core-2.16.0.jar");
    }
  }

  private static boolean isIntrafindService(Path path) {
    return path.getParent().getParent().resolve("log4j.properties").toFile().exists() &&
        path.getParent().getParent().resolve("conf/wrapper.conf").toFile().exists();
  }

  private static boolean isIntrafindWebapp(Path path) {
    return "iFinder5".equals(path.getParent().getParent().getParent().getFileName().toString()) &&
        path.getParent().getParent().resolve("classes/log4j.properties").toFile().exists();
  }

  private static boolean isIntrafindApp(Path path) {
    return path.getParent().getParent().resolve("conf/log4j.properties").toFile().exists();
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

  private static void replace(Path oldFile, String replacement, List<Path> backups, List<Path> addedFiles) {
    delete(oldFile, backups, addedFiles);
    final Path pathReplacement = oldFile.getParent().resolve(replacement);
    try {
      exportResource(replacement, pathReplacement);
      addedFiles.add(pathReplacement);
    } catch (Exception e) {
      System.err.println("Could not write to " + pathReplacement + " restoring changes...");
      restoreAndExit(backups, addedFiles);
    }
    System.out.println("Replaced " + oldFile + " with " + replacement);
  }

  private static Path delete(Path oldFile, List<Path> backups, List<Path> addedFiles) {
    try {
      final Path backupPath = Paths.get(oldFile + BACKUP_SUFFIX);
      Files.move(oldFile, backupPath);
      backups.add(backupPath);
      System.out.println("Backed up " + oldFile);
      return backupPath;
    } catch (Exception e) {
      System.err.println("Could not move " + oldFile + "! Make sure you have write permissions and the file is not in use. Restoring changes...");
      restoreAndExit(backups, addedFiles);
      return null;
    }
  }

  @SuppressWarnings("ConstantConditions")
  private static void clean(Path fatJar, List<Path> backups, List<Path> addedFiles, boolean allowDuplicates) {
    final Path backupPath = delete(fatJar, backups, addedFiles);
    try (final InputStream fileInputStream = Files.newInputStream(backupPath);
         final BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
         final OutputStream fileOutputStream = Files.newOutputStream(fatJar);
         final BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream)) {
      copyZipWithoutVulnerableClasses(bufferedInputStream, bufferedOutputStream, allowDuplicates);
    } catch (Exception e) {
      System.err.println("Could not remove vulnerable classes from " + fatJar + ". Restoring changes...");
      if (e instanceof ZipException && e.getMessage().contains("duplicate entry:")) {
        System.err.println("Please try again with the 'allow-duplicates' option activated. This might cause warnings about illegal reflection occurring. Those may be ignored.");
      }
      try {
        Files.delete(fatJar);
      } catch (IOException ex) {
        System.err.println("Failed to delete incomplete " + fatJar);
      }
      restoreAndExit(backups, addedFiles);
    }
  }

  private static void addFile(Path file, String content, List<Path> backups, List<Path> addedFiles) {
    try {
      exportResource(content, file);
      addedFiles.add(file);
    } catch (IOException e) {
      System.err.println("Could not write to " + file + ". Exception: " + e.getMessage() + " Restoring changes...");
      restoreAndExit(backups, addedFiles);
    }
  }

  private static void appendToFile(Path path, String content, List<Path> backups, List<Path> addedFiles) {
    try (OutputStream outputStream = Files.newOutputStream(path, StandardOpenOption.APPEND);
         Writer writer = new OutputStreamWriter(outputStream);
         BufferedWriter bufferedWriter = new BufferedWriter(writer)) {
      final Path backupPath = Paths.get(path + BACKUP_SUFFIX);
      Files.copy(path, backupPath);
      backups.add(backupPath);
      bufferedWriter.write(content);
    } catch (IOException e) {
      System.err.println("Could not write to " + path + ". Exception: " + e.getMessage() + " Restoring changes...");
      restoreAndExit(backups, addedFiles);
    }
  }

  @SuppressWarnings("ConstantConditions")
  private static void replaceInFile(Path path, Map<String, String> replacements, List<Path> backups, List<Path> addedFiles) {
    final Path backupPath = delete(path, backups, addedFiles);
    try (final InputStream inputStream = Files.newInputStream(backupPath);
         final Reader reader = new InputStreamReader(inputStream);
         final BufferedReader bufferedReader = new BufferedReader(reader);
         final OutputStream outputStream = Files.newOutputStream(path);
         final Writer writer = new OutputStreamWriter(outputStream);
         final BufferedWriter bufferedWriter = new BufferedWriter(writer)) {
      bufferedReader.lines()
          .map(line -> applyReplacementsToString(line, replacements))
          .forEachOrdered(str -> {
            try {
              bufferedWriter.write(str);
            } catch (IOException e) {
              throw new UncheckedIOException(e);
            }
          });
    } catch (Exception e) {
      System.err.println("Could not modify file " + path + ". Exception: " + e.getMessage() + " Restoring changes...");
      restoreAndExit(backups, addedFiles);
    }
  }

  private static String applyReplacementsToString(String text, Map<String, String> replacements) {
    String resultingText = text;
    for (Map.Entry<String, String> replacement : replacements.entrySet()) {
      resultingText = resultingText.replace(replacement.getKey(), replacement.getValue());
    }
    return resultingText;
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

  @SuppressWarnings({"unchecked", "ConstantConditions"})
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
      final ZipEntry newEntry = new ZipEntry(entry.getName());
      Optional.ofNullable(entry.getComment()).ifPresent(newEntry::setComment);
      Optional.ofNullable(entry.getCreationTime()).ifPresent(newEntry::setCreationTime);
      Optional.ofNullable(entry.getExtra()).ifPresent(newEntry::setExtra);
      Optional.ofNullable(entry.getLastAccessTime()).ifPresent(newEntry::setLastAccessTime);
      Optional.ofNullable(entry.getLastModifiedTime()).ifPresent(newEntry::setLastModifiedTime);
      Optional.ofNullable(entry.getTime()).ifPresent(newEntry::setTime);
      zipOutputStream.putNextEntry(newEntry);
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

  private static void restoreAndExit(List<Path> backups, List<Path> addedFiles) {
    for (Path backup : backups) {
      final Path restorePath = Paths.get(backup.toString().replaceAll("(\\Q" + BACKUP_SUFFIX + "\\E)+$", ""));
      try {
        Files.move(backup, restorePath, REPLACE_EXISTING);
      } catch (Exception e) {
        System.err.println("Restoring " + backup + " failed!");
        e.printStackTrace();
      }
    }
    for (Path addedFile : addedFiles) {
      try {
        Files.delete(addedFile);
      } catch (IOException e) {
        System.err.println("Deleting " + addedFile + " failed!");
        e.printStackTrace();
      }
    }
    System.exit(1);
  }

  private static void deleteBackups(Path dir, List<Path> backups) throws IOException {
    for (Path backup : backups) {
      deleteBackup(backup);
    }
    Files.walk(dir)
        .filter(path -> path.toString().endsWith(BACKUP_SUFFIX))
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
