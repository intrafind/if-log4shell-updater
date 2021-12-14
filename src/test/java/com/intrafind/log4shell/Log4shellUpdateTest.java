package com.intrafind.log4shell;

import org.hamcrest.CustomMatcher;
import org.hamcrest.Matcher;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

public class Log4shellUpdateTest {

  private static final PrintStream ORIGINAL_OUT = System.out;

  private Path tempDir;
  private ByteArrayOutputStream systemOut;

  @Before
  public void before() throws IOException {
    systemOut = new ByteArrayOutputStream();
    System.setOut(new PrintStream(systemOut));

    tempDir = Files.createTempDirectory("test-log4shell");
    Files.createFile(tempDir.resolve("log4j-1.2-api-2.11.0.jar"));
    Files.createFile(tempDir.resolve("log4j-api-2.11.0.jar"));
    Files.createFile(tempDir.resolve("log4j-core-2.11.0.jar"));
    Files.createFile(tempDir.resolve("log4j-jcl-2.11.0.jar"));
    Files.createFile(tempDir.resolve("log4j-layout-template-json-2.11.0.jar"));
    Files.createFile(tempDir.resolve("log4j-slf4j-impl-2.11.0.jar"));
    Files.createFile(tempDir.resolve("log4j-1.2.17.jar"));
    final Path service = Files.createDirectory(tempDir.resolve("service"));
    Files.createFile(service.resolve("log4j-1.2-api-2.11.0.jar"));
    Files.createFile(service.resolve("log4j-api-2.11.0.jar"));
    Files.createFile(service.resolve("log4j-core-2.11.0.jar"));
    Files.createFile(service.resolve("log4j-jcl-2.11.0.jar"));
    Files.createFile(service.resolve("log4j-layout-template-json-2.11.0.jar"));
    Files.createFile(service.resolve("log4j-slf4j-impl-2.11.0.jar"));
    Files.createFile(service.resolve("elasticsearch-sql-cli-7.10.2.jar"));
    Files.createFile(service.resolve("log4j-1.2.17.jar"));
    final ZipOutputStream fatJar = new ZipOutputStream(new FileOutputStream(service.resolve("fat-jar.jar").toString()));
    fatJar.putNextEntry(new ZipEntry("org/apache/logging/log4j/core/lookup/JndiLookup.class"));
    fatJar.close();
    final ZipOutputStream deepFatJar = new ZipOutputStream(new FileOutputStream(service.resolve("deep-fat-jar.jar").toString()));
    deepFatJar.putNextEntry(new ZipEntry("log4j.jar"));
    final ZipOutputStream deepZipOutputStream = new ZipOutputStream(deepFatJar);
    deepZipOutputStream.putNextEntry(new ZipEntry("org/apache/logging/log4j/core/lookup/JndiLookup.class"));
    deepZipOutputStream.closeEntry();
    deepFatJar.putNextEntry(new ZipEntry("z.zzz"));
    deepFatJar.close();
    final Path serviceSubOld = Files.createDirectory(service.resolve("subOld"));
    Files.createFile(serviceSubOld.resolve("log4j-1.2-api-2.11.0.jar"));
    Files.createFile(serviceSubOld.resolve("log4j-api-2.11.0.jar"));
    Files.createFile(serviceSubOld.resolve("log4j-core-2.11.0.jar"));
    Files.createFile(serviceSubOld.resolve("log4j-jcl-2.11.0.jar"));
    Files.createFile(serviceSubOld.resolve("log4j-layout-template-json-2.11.0.jar"));
    Files.createFile(serviceSubOld.resolve("log4j-slf4j-impl-2.11.0.jar"));
    Files.createFile(serviceSubOld.resolve("log4j-1.2.17.jar"));
    final Path serviceSubNew = Files.createDirectory(service.resolve("subNew"));
    Files.createFile(serviceSubNew.resolve("log4j-core-2.16.0.jar"));
    final Path serviceSubNewer = Files.createDirectory(service.resolve("subNewer"));
    Files.createFile(serviceSubNewer.resolve("log4j-core-2.30.0.jar"));
  }

  @SuppressWarnings("ConstantConditions")
  @Test
  public void testDryRun() throws IOException {
    Log4shellUpdate.main(new String[]{"-p", tempDir.resolve("service").toString(), "-d"});

    assertThat(tempDir.resolve("service").toFile().list().length, is(equalTo(13)));
    assertThat(tempDir.resolve("log4j-core-2.11.0.jar"), exists());
    assertThat(tempDir.resolve("log4j-core-2.16.0.jar"), not(exists()));
    assertThat(tempDir.resolve("service/log4j-core-2.11.0.jar"), exists());
    assertThat(tempDir.resolve("service/log4j-core-2.16.0.jar"), not(exists()));
    assertThat(tempDir.resolve("service/elasticsearch-sql-cli-7.10.2.jar"), exists());
    assertThat(tempDir.resolve("service/subOld/log4j-core-2.11.0.jar"), exists());
    assertThat(tempDir.resolve("service/subOld/log4j-core-2.16.0.jar"), not(exists()));
    assertThat(tempDir.resolve("service/subNew/log4j-core-2.16.0.jar"), exists());
    assertThat(tempDir.resolve("service/subNewer/log4j-core-2.30.0.jar"), exists());
    assertThat(tempDir.resolve("service/subNewer/log4j-core-2.16.0.jar"), not(exists()));

    final String output = systemOut.toString();
    assertThat(output, containsString("deep-fat-jar.jar"));
    assertThat(output, containsString("fat-jar.jar"));
  }

  @SuppressWarnings("ConstantConditions")
  @Test
  public void test() throws IOException {
    Log4shellUpdate.main(new String[]{"-p", tempDir.resolve("service").toString()});

    assertThat(tempDir.resolve("service").toFile().list().length, is(equalTo(19)));
    assertThat(tempDir.resolve("log4j-core-2.11.0.jar"), exists());
    assertThat(tempDir.resolve("log4j-core-2.16.0.jar"), not(exists()));
    assertThat(tempDir.resolve("service/log4j-core-2.11.0.jar"), not(exists()));
    assertThat(tempDir.resolve("service/log4j-core-2.16.0.jar"), exists());
    assertThat(tempDir.resolve("service/log4j-core-2.11.0.jar.bak"), exists());
    assertThat(tempDir.resolve("service/elasticsearch-sql-cli-7.10.2.jar"), not(exists()));
    assertThat(tempDir.resolve("service/elasticsearch-sql-cli-7.10.2.jar.bak"), exists());
    assertThat(tempDir.resolve("service/subOld/log4j-core-2.11.0.jar"), not(exists()));
    assertThat(tempDir.resolve("service/subOld/log4j-core-2.16.0.jar"), exists());
    assertThat(tempDir.resolve("service/subOld/log4j-core-2.11.0.jar.bak"), exists());
    assertThat(tempDir.resolve("service/subNew/log4j-core-2.16.0.jar"), exists());
    assertThat(tempDir.resolve("service/subNewer/log4j-core-2.30.0.jar"), exists());
    assertThat(tempDir.resolve("service/subNewer/log4j-core-2.16.0.jar"), not(exists()));

    Log4shellUpdate.main(new String[]{"-p", tempDir.resolve("service").toString(), "-b"});
    assertThat(tempDir.resolve("service").toFile().list().length, is(equalTo(12)));
    assertThat(tempDir.resolve("service/log4j-core-2.11.0.jar.bak"), not(exists()));
    assertThat(tempDir.resolve("service/subOld/log4j-core-2.11.0.jar.bak"), not(exists()));

  }

  @SuppressWarnings("ConstantConditions")
  @Test
  public void testDeleteBackups() throws IOException {
    Log4shellUpdate.main(new String[]{"-p", tempDir.resolve("service").toString(), "-b"});

    assertThat(tempDir.resolve("service").toFile().list().length, is(equalTo(12)));
    assertThat(tempDir.resolve("log4j-core-2.11.0.jar"), exists());
    assertThat(tempDir.resolve("log4j-core-2.16.0.jar"), not(exists()));
    assertThat(tempDir.resolve("service/log4j-core-2.11.0.jar"), not(exists()));
    assertThat(tempDir.resolve("service/log4j-core-2.16.0.jar"), exists());
    assertThat(tempDir.resolve("service/log4j-core-2.11.0.jar.bak"), not(exists()));
    assertThat(tempDir.resolve("service/subOld/log4j-core-2.11.0.jar"), not(exists()));
    assertThat(tempDir.resolve("service/subOld/log4j-core-2.16.0.jar"), exists());
    assertThat(tempDir.resolve("service/subOld/log4j-core-2.11.0.jar.bak"), not(exists()));
    assertThat(tempDir.resolve("service/subNew/log4j-core-2.16.0.jar"), exists());
    assertThat(tempDir.resolve("service/subNewer/log4j-core-2.30.0.jar"), exists());
    assertThat(tempDir.resolve("service/subNewer/log4j-core-2.16.0.jar"), not(exists()));
  }

  @After
  public void after() throws IOException {
    Files.walkFileTree(tempDir, new SimpleFileVisitor<Path>() {
      @Override
      public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
        Files.delete(file);
        return FileVisitResult.CONTINUE;
      }

      @Override
      public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
        Files.delete(dir);
        return FileVisitResult.CONTINUE;
      }
    });
    System.setOut(ORIGINAL_OUT);
  }

  private static <T> Matcher<T> exists() {
    return new CustomMatcher<T>("exists") {
      @Override
      public boolean matches(Object item) {
        if (item instanceof Path) {
          return ((Path) item).toFile().exists();
        } else {
          return false;
        }
      }
    };
  }
}
