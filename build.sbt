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
  val boilerplate = Def.setting("io.github.arashi01" %%% "boilerplate" % "0.7.0")
  val `jsoniter-scala-core` = Def.setting("com.github.plokhotnyuk.jsoniter-scala" %%% "jsoniter-scala-core" % "2.38.9")
  val `jsoniter-scala-macros` = Def.setting("com.github.plokhotnyuk.jsoniter-scala" %%% "jsoniter-scala-macros" % "2.38.9")
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

val `kufuli-js-shared` =
  project
    .in(file("modules/js-shared"))
    .enablePlugins(ScalaJSPlugin)
    .dependsOn(`kufuli-core`.js)
    .settings(compilerSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(jsSettings)
    .settings(description := "Shared JS utilities for kufuli browser and Node.js backends")

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
    .nativeSettings(nativeCryptoLinkSettings)
    .jsSettings(jsSettings)
    .jsSettings(Compile / doc / sources := Nil) // Scala 3 doc compiler cannot resolve overloaded @js.native methods in NodeCrypto
    .jsConfigure(_.dependsOn(`kufuli-js-shared`))
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

val `kufuli-zio-browser` =
  project
    .in(file("modules/zio-browser"))
    .enablePlugins(ScalaJSPlugin)
    .dependsOn(`kufuli-js-shared`)
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(jsSettings)
    .settings(description := "Web Crypto (SubtleCrypto) backend for kufuli")
    .settings(libraryDependencies += libraries.zio.value)
    .settings(Compile / unmanagedSourceDirectories += baseDirectory.value / ".." / "zio" / "shared" / "src" / "main" / "scala")
    .settings(Test / jsEnv := new jsenv.playwright.PWEnv(browserName = "chromium", headless = true, showLogs = true))
    .dependsOn(`kufuli-testkit`.js % Test)

val `kufuli-tests` =
  crossProject(JVMPlatform, JSPlatform, NativePlatform)
    .withoutSuffixFor(JVMPlatform)
    .crossType(CrossType.Full)
    .in(file("modules/tests"))
    .dependsOn(`kufuli-zio`, `kufuli-testkit`)
    .enablePlugins(WycheproofPlugin)
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publish / skip := true)
    .settings(description := "Cross-platform integration tests for kufuli")
    .nativeSettings(nativeSettings)
    .nativeSettings(nativeCryptoLinkSettings)
    .jsSettings(jsSettings)
    .settings(
      libraryDependencies ++= List(
        libraries.zio.value,
        libraries.`jsoniter-scala-core`.value % Test,
        libraries.`jsoniter-scala-macros`.value % Test
      )
    )
    .settings(
      WycheproofPlugin.autoImport.wycheproofTargetPackage := "kufuli.tests.wycheproof",
      WycheproofPlugin.autoImport.wycheproofVectorFiles := Seq(
        // ECDSA (DER)
        "ecdsa_secp256r1_sha256_test.json",
        "ecdsa_secp384r1_sha384_test.json",
        "ecdsa_secp521r1_sha512_test.json",
        // ECDSA (P1363)
        "ecdsa_secp256r1_sha256_p1363_test.json",
        "ecdsa_secp384r1_sha384_p1363_test.json",
        "ecdsa_secp521r1_sha512_p1363_test.json",
        // Ed25519
        "ed25519_test.json",
        // RSA PKCS#1
        "rsa_signature_2048_sha256_test.json",
        "rsa_signature_2048_sha384_test.json",
        "rsa_signature_2048_sha512_test.json",
        // RSA-PSS
        "rsa_pss_2048_sha256_mgf1_32_test.json",
        "rsa_pss_2048_sha384_mgf1_48_test.json",
        "rsa_pss_4096_sha512_mgf1_64_test.json",
        // HMAC
        "hmac_sha256_test.json",
        "hmac_sha384_test.json",
        "hmac_sha512_test.json"
      )
    )

val `kufuli-jvm` =
  project
    .in(file(".jvm"))
    .settings(publish / skip := true)
    .aggregate(
      `kufuli-core`.jvm,
      `kufuli-zio`.jvm,
      `kufuli-testkit`.jvm,
      `kufuli-tests`.jvm
    )

val `kufuli-js` =
  project
    .in(file(".js"))
    .settings(publish / skip := true)
    .aggregate(
      `kufuli-core`.js,
      `kufuli-js-shared`,
      `kufuli-zio`.js,
      `kufuli-zio-browser`,
      `kufuli-testkit`.js,
      `kufuli-tests`.js
    )

val `kufuli-native` =
  project
    .in(file(".native"))
    .settings(publish / skip := true)
    .aggregate(
      `kufuli-core`.native,
      `kufuli-zio`.native,
      `kufuli-testkit`.native,
      `kufuli-tests`.native
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

// Platform crypto library linking - only for modules containing or depending on C FFI code
def nativeCryptoLinkSettings = List(
  nativeConfig ~= { c =>
    val os = System.getProperty("os.name").toLowerCase
    if (os.contains("linux"))
      c.withLinkingOptions(c.linkingOptions ++ Seq("-lssl", "-lcrypto"))
    else if (os.contains("mac") || os.contains("darwin"))
      c.withLinkingOptions(c.linkingOptions ++ Seq("-framework", "Security", "-framework", "CoreFoundation"))
    else if (os.contains("win"))
      c.withLinkingOptions(c.linkingOptions ++ Seq("-lbcrypt"))
    else
      c
  }
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
  Compile / doc / scalacOptions := Nil, // doc compiler does not support -Yexplicit-nulls, -Werror, etc.
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

def publishSettings: List[Setting[?]] = pgpSettings ++: aetherSettings ++: List(
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

// Maven-native snapshot deployment via sbt-aether-deploy (timestamped SNAPSHOTs with maven-metadata.xml)
def aetherSettings: List[Setting[?]] = List(
  credentials ++= {
    val user = sys.env.get("SONATYPE_USERNAME")
    val pass = sys.env.get("SONATYPE_PASSWORD")
    (user, pass) match {
      case (Some(u), Some(p)) => List(Credentials("central-snapshots", "central.sonatype.com", u, p))
      case _                  => Nil
    }
  }
)

addCommandAlias("format", "scalafixAll; scalafmtAll; scalafmtSbt; headerCreateAll")
addCommandAlias("check", "scalafixAll --check; scalafmtCheckAll; scalafmtSbtCheck; headerCheckAll")
