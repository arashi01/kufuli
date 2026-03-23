inThisBuild(
  List(
    scalaVersion := "3.8.2",
    organization := "io.github.arashi01",
    startYear := Some(2026),
    homepage := Some(url("https://github.com/arashi01/kufuli")),
    semanticdbEnabled := true,
    version := versionSetting.value,
    dynver := versionSetting.toTaskable.toTask.value,
    versionScheme := Some("semver-spec"),
    licenses := List("MIT" -> url("https://opensource.org/licenses/MIT")),
    scmInfo := Some(
      ScmInfo(
        url("https://github.com/arashi01/kufuli"),
        "scm:git:https://github.com/arashi01/kufuli.git",
        Some("scm:git:git@github.com:arashi01/kufuli.git")
      )
    )
  ) ++ formattingSettings
)

val libraries = new {
  val boilerplate = Def.setting("io.github.arashi01" %%% "boilerplate" % "0.6.0")
  val munit = Def.setting("org.scalameta" %%% "munit" % "1.2.4")
  val `munit-scalacheck` = Def.setting("org.scalameta" %%% "munit-scalacheck" % "1.2.0")
  val `munit-zio` = Def.setting("com.github.poslegm" %%% "munit-zio" % "0.4.0")
  val `scala-java-time` = Def.setting("io.github.cquiroz" %%% "scala-java-time" % "2.6.0")
  val zio = Def.setting("dev.zio" %%% "zio" % "2.1.24")
}

val `kufuli-core` =
  crossProject(JVMPlatform, JSPlatform, NativePlatform)
    .withoutSuffixFor(JVMPlatform)
    .crossType(CrossType.Pure)
    .in(file("modules/core"))
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(description := "Pure-Scala cross-platform cryptographic primitives and algorithm models")
    .nativeSettings(nativeSettings)
    .jsSettings(jsSettings)
    .settings(libraryDependencies += libraries.boilerplate.value)

val `kufuli-zio` =
  crossProject(JVMPlatform, JSPlatform, NativePlatform)
    .withoutSuffixFor(JVMPlatform)
    .crossType(CrossType.Full)
    .in(file("modules/zio"))
    .dependsOn(`kufuli-core`)
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(description := "ZIO typeclass traits and platform-specific crypto backends")
    .nativeSettings(nativeSettings)
    .jsSettings(jsSettings)
    .settings(libraryDependencies += libraries.zio.value)

val `kufuli-zio-browser` =
  project
    .in(file("modules/zio-browser"))
    .enablePlugins(ScalaJSPlugin)
    .dependsOn(`kufuli-core`.js)
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(description := "Web Crypto (SubtleCrypto) backend for kufuli")
    .settings(libraryDependencies += libraries.zio.value)

val `kufuli-testkit` =
  crossProject(JVMPlatform, JSPlatform, NativePlatform)
    .withoutSuffixFor(JVMPlatform)
    .crossType(CrossType.Pure)
    .in(file("modules/testkit"))
    .dependsOn(`kufuli-core`)
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(description := "Abstract test suites and RFC vectors for kufuli crypto backends")
    .nativeSettings(nativeSettings)
    .jsSettings(jsSettings)
    .settings(libraryDependencies += libraries.munit.value)

val `kufuli-zio-tests` =
  crossProject(JVMPlatform, JSPlatform, NativePlatform)
    .withoutSuffixFor(JVMPlatform)
    .crossType(CrossType.Full)
    .in(file("modules/zio-tests"))
    .dependsOn(`kufuli-zio`, `kufuli-testkit`)
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publish / skip := true)
    .settings(description := "ZIO test instantiation for kufuli testkit")
    .nativeSettings(nativeSettings)
    .jsSettings(jsSettings)
    .settings(libraryDependencies += libraries.zio.value)

val `kufuli-jvm` =
  project
    .in(file(".jvm"))
    .settings(publish / skip := true)
    .aggregate(
      `kufuli-core`.jvm,
      `kufuli-zio`.jvm,
      `kufuli-testkit`.jvm,
      `kufuli-zio-tests`.jvm
    )

val `kufuli-js` =
  project
    .in(file(".js"))
    .settings(publish / skip := true)
    .aggregate(
      `kufuli-core`.js,
      `kufuli-zio`.js,
      `kufuli-zio-browser`,
      `kufuli-testkit`.js,
      `kufuli-zio-tests`.js
    )

val `kufuli-native` =
  project
    .in(file(".native"))
    .settings(publish / skip := true)
    .aggregate(
      `kufuli-core`.native,
      `kufuli-zio`.native,
      `kufuli-testkit`.native,
      `kufuli-zio-tests`.native
    )

val `kufuli-root` =
  project
    .in(file("."))
    .settings(publish / skip := true)
    .aggregate(
      `kufuli-jvm`,
      `kufuli-js`,
      `kufuli-native`
    )

def jsSettings = List(
  scalaJSLinkerConfig ~= { _.withModuleKind(ModuleKind.ESModule) }
)

def nativeSettings = List(
  dependencyOverrides += "org.scala-native" %%% "test-interface" % buildinfo.BuildInfo.scalaNativeVersion % Test
)

def baseCompilerOptions = List(
  // Language features
  "-language:experimental.macros",
  "-language:higherKinds",
  "-language:implicitConversions",
  "-language:strictEquality",

  // Kind projector / macros
  "-Xkind-projector",
  "-Xmax-inlines:64",

  // Core checks
  "-unchecked",
  "-deprecation",
  "-feature",
  "-explain",

  // Warning flags
  "-Wvalue-discard",
  "-Wnonunit-statement",
  "-Wunused:implicits",
  "-Wunused:explicits",
  "-Wunused:imports",
  "-Wunused:locals",
  "-Wunused:params",
  "-Wunused:privates",

  // Scala 3-specific checks
  "-Yrequire-targetName",
  "-Ycheck-reentrant",
  "-Ycheck-mods"
)

def compilerOptions = baseCompilerOptions ++ List(
  "-Yexplicit-nulls",
  "-Xcheck-macros",
  "-Werror"
)

def compilerSettings = List(
  Compile / compile / scalacOptions ++= compilerOptions,
  Test / compile / scalacOptions ++= baseCompilerOptions,
  Compile / doc / scalacOptions := Nil,
  Test / doc / scalacOptions := Nil
)

def formattingSettings = List(
  scalafmtDetailedError := true,
  scalafmtPrintDiff := true
)

def unitTestSettings: List[Setting[?]] = List(
  libraryDependencies ++= List(
    libraries.munit.value % Test,
    libraries.`munit-scalacheck`.value % Test,
    libraries.`scala-java-time`.value % Test,
    libraries.`munit-zio`.value % Test
  ),
  testFrameworks += new TestFramework("munit.Framework")
)

def fileHeaderSettings: List[Setting[?]] =
  List(
    headerLicense := {
      val developmentTimeline = {
        import java.time.Year
        val start = startYear.value.get
        val current: Int = Year.now.getValue
        if (start == current) s"$current" else s"$start, $current"
      }
      Some(HeaderLicense.MIT(developmentTimeline, "Ali Rashid."))
    },
    headerEmptyLine := false
  )

def pgpSettings: List[Setting[?]] = List(
  PgpKeys.pgpSelectPassphrase := None,
  usePgpKeyHex(System.getenv("SIGNING_KEY_ID"))
)

def versionSetting: Def.Initialize[String] = Def.setting(
  dynverGitDescribeOutput.value.mkVersion(
    (in: sbtdynver.GitDescribeOutput) =>
      if (!in.isSnapshot()) in.ref.dropPrefix
      else {
        val ref = in.ref.dropPrefix
        // Strip pre-release or build metadata (e.g., "-m.1" or "+build.5")
        val base = ref.takeWhile(c => c != '-' && c != '+')
        val numericParts =
          base.split("\\.").toList.map(_.trim).flatMap(s => scala.util.Try(s.toInt).toOption)

        if (numericParts.nonEmpty) {
          val incremented = numericParts.updated(numericParts.length - 1, numericParts.last + 1)
          s"${incremented.mkString(".")}-SNAPSHOT"
        } else {
          s"$base-SNAPSHOT"
        }
      },
    "SNAPSHOT"
  )
)

def publishSettings: List[Setting[?]] = pgpSettings ++: List(
  packageOptions += Package.ManifestAttributes(
    "Build-Jdk" -> System.getProperty("java.version"),
    "Specification-Title" -> name.value,
    "Specification-Version" -> Keys.version.value,
    "Implementation-Title" -> name.value
  ),
  publishTo := {
    if (Keys.version.value.toLowerCase.contains("snapshot"))
      Some("central-snapshots".at("https://central.sonatype.com/repository/maven-snapshots/"))
    else localStaging.value
  },
  pomIncludeRepository := (_ => false),
  publishMavenStyle := true,
  developers := List(
    Developer(
      "arashi01",
      "Ali Rashid",
      "https://github.com/arashi01",
      url("https://github.com/arashi01")
    )
  )
)

addCommandAlias("format", "scalafixAll; scalafmtAll; scalafmtSbt; headerCreateAll")
addCommandAlias("check", "scalafixAll --check; scalafmtCheckAll; scalafmtSbtCheck; headerCheckAll")
