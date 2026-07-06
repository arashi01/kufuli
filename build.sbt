scalaVersion := scala3
organization := "io.github.arashi01"
startYear := Some(2026)
homepage := Some(url("https://github.com/arashi01/kufuli"))
semanticdbEnabled := true
versionScheme := Some("semver-spec")
licenses := List("MIT" -> url("https://opensource.org/licenses/MIT"))
scmInfo := Some(
  ScmInfo(
    url("https://github.com/arashi01/kufuli"),
    "scm:git:https://github.com/arashi01/kufuli.git",
    Some("scm:git:git@github.com:arashi01/kufuli.git")
  )
)
formattingSettings

def scala3 = "3.9.0-RC1"
val boilerplate: ModuleID = "io.github.arashi01" %% "boilerplate" % "0.8.0"
val `jsoniter-scala-core`: ModuleID = "com.github.plokhotnyuk.jsoniter-scala" %% "jsoniter-scala-core" % "2.38.12"
val `jsoniter-scala-macros`: ModuleID = "com.github.plokhotnyuk.jsoniter-scala" %% "jsoniter-scala-macros" % "2.38.12"
val munit: ModuleID = "org.scalameta" %% "munit" % "1.3.0"
val `munit-scalacheck`: ModuleID = "org.scalameta" %% "munit-scalacheck" % "1.3.0"
val `munit-zio`: ModuleID = "com.github.poslegm" %% "munit-zio" % "0.4.0"
val `scala-java-time`: ModuleID = "io.github.cquiroz" %% "scala-java-time" % "2.6.0"
val zio: ModuleID = "dev.zio" %% "zio" % "2.1.26"

val `kufuli-core` =
  projectMatrix
    .in(file("modules/core"))
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(description := "Pure-Scala cross-platform cryptographic primitives and algorithm models")
    .settings(libraryDependencies += boilerplate)
    .jvmPlatform(Seq(scala3))
    .jsPlatform(Seq(scala3), jsSettings)
    .snxPlatform(Seq(scala3), NativePlatformPlugin.schemeSettings)

val `kufuli-js-shared` =
  project
    .in(file("modules/js-shared"))
    .enablePlugins(ScalaJSPlugin)
    .dependsOn(`kufuli-core`.js(scala3))
    .settings(compilerSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(jsSettings)
    .settings(description := "Shared JS utilities for kufuli browser and Node.js backends")

// JS rows share `src/main/scala` but diverge runtime target: Node vs Browsers (Web Crypto).
val `kufuli-zio` =
  projectMatrix
    .in(file("modules/zio"))
    .dependsOn(`kufuli-core`)
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(description := "ZIO typeclass traits and platform-specific crypto backends")
    .settings(libraryDependencies += zio)
    .jvmPlatform(Seq(scala3))
    .jsPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) => p.settings(jsSettings).settings(jsDocOff).dependsOn(`kufuli-js-shared`)
    )
    .jsPlatform(
      Seq(scala3),
      Seq(WebCryptoAxis),
      (p: Project) =>
        p.settings(jsSettings)
          .settings(jsDocOff)
          .settings(moduleName := "kufuli-zio-browser")
          .dependsOn(`kufuli-js-shared`)
    )
    .snxPlatform(Seq(scala3), NativePlatformPlugin.cryptoSettings)

val `kufuli-testkit` =
  projectMatrix
    .in(file("modules/testkit"))
    .dependsOn(`kufuli-core`)
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publishSettings)
    .settings(description := "Abstract test suites and RFC vectors for kufuli crypto backends")
    .settings(libraryDependencies += munit)
    .jvmPlatform(Seq(scala3))
    .jsPlatform(Seq(scala3), jsSettings)
    .snxPlatform(Seq(scala3), NativePlatformPlugin.schemeSettings)

// Wycheproof JSON vector files embedded into every kufuli-tests row (JVM, JS Node.js, Web Crypto
// browser, Scala Native), so the same shared test suites run uniformly across every backend.
val wycheproofVectors = Seq(
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

// zio rows differ only by a weak axis, so ambiguous to matrix-level resolution. Wire directly per row.
val `kufuli-tests` =
  projectMatrix
    .in(file("modules/tests"))
    .dependsOn(`kufuli-testkit`)
    .enablePlugins(WycheproofPlugin)
    .settings(compilerSettings)
    .settings(unitTestSettings)
    .settings(fileHeaderSettings)
    .settings(publish / skip := true)
    .settings(description := "Cross-platform integration tests for kufuli")
    .settings(libraryDependencies += zio)
    .settings(libraryDependencies += `jsoniter-scala-core` % Test)
    .settings(libraryDependencies += `jsoniter-scala-macros` % Test)
    .settings(
      WycheproofPlugin.autoImport.wycheproofTargetPackage := "kufuli.tests.wycheproof",
      WycheproofPlugin.autoImport.wycheproofVectorFiles := wycheproofVectors
    )
    .jvmPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) => p.dependsOn(`kufuli-zio`.jvm(scala3))
    )
    .jsPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) => p.settings(jsSettings).dependsOn(`kufuli-zio`.js(scala3))
    )
    .jsPlatform(
      Seq(scala3),
      Seq(WebCryptoAxis),
      (p: Project) =>
        p.settings(jsSettings)
          .settings(Test / jsEnv := Def.uncached(new jsenv.playwright.PWEnv(browserName = "chromium", headless = true, showLogs = true)))
          .dependsOn(`kufuli-zio`.finder(VirtualAxis.js, WebCryptoAxis)(scala3))
    )
    .snxPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) => p.settings(NativePlatformPlugin.testLinkSettings).dependsOn(`kufuli-zio`.native(scala3))
    )

val `kufuli-jvm` =
  projectMatrix
    .in(file(".jvm"))
    .jvmPlatform(Seq(scala3))
    .settings(publish / skip := true)
    .aggregate(`kufuli-core`, `kufuli-zio`, `kufuli-testkit`, `kufuli-tests`)

val `kufuli-js` =
  projectMatrix
    .in(file(".js"))
    .jsPlatform(
      Seq(scala3),
      Seq.empty[VirtualAxis],
      (p: Project) =>
        p.aggregate(
          `kufuli-js-shared`,
          `kufuli-zio`.finder(VirtualAxis.js, WebCryptoAxis)(scala3),
          `kufuli-tests`.finder(VirtualAxis.js, WebCryptoAxis)(scala3)
        )
    )
    .defaultAxes(VirtualAxis.js, VirtualAxis.scalaABIVersion(scala3))
    .settings(publish / skip := true)
    .aggregate(`kufuli-core`, `kufuli-zio`, `kufuli-testkit`, `kufuli-tests`)

val `kufuli-native` =
  projectMatrix
    .in(file(".native"))
    .snxPlatform(Seq(scala3))
    .defaultAxes(VirtualAxis.native, VirtualAxis.scalaABIVersion(scala3))
    .settings(publish / skip := true)
    .aggregate(`kufuli-core`, `kufuli-zio`, `kufuli-testkit`, `kufuli-tests`)

val `kufuli-root` =
  projectMatrix
    .in(file("."))
    .settings(publish / skip := true)
    .aggregate(`kufuli-jvm`, `kufuli-js`, `kufuli-native`)

def jsSettings: List[Setting[?]] = List(
  scalaJSLinkerConfig ~= { _.withModuleKind(ModuleKind.ESModule) }
)

// TODO: The Scala 3 doc compiler cannot resolve the overloaded @js.native methods in the Node/Web Crypto
def jsDocOff: List[Setting[?]] = List(Compile / doc / sources := Nil)

def baseCompilerOptions = List(
  "-language:experimental.macros",
  "-language:higherKinds",
  "-language:implicitConversions",
  "-language:strictEquality",
  "-Xkind-projector",
  "-Xmax-inlines:64",
  "-unchecked",
  "-deprecation",
  "-feature",
  "-explain",
  "-Wvalue-discard",
  "-Wnonunit-statement",
  "-Wunused:implicits",
  "-Wunused:explicits",
  "-Wunused:imports",
  "-Wunused:locals",
  "-Wunused:params",
  "-Wunused:privates",
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
  libraryDependencies += munit % Test,
  libraryDependencies += `munit-scalacheck` % Test,
  libraryDependencies += `scala-java-time` % Test,
  libraryDependencies += `munit-zio` % Test,
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

def publishSettings: List[Setting[?]] = List(
  packageOptions += Package.ManifestAttributes(
    "Build-Jdk" -> System.getProperty("java.version"),
    "Specification-Title" -> name.value,
    "Specification-Version" -> Keys.version.value,
    "Implementation-Title" -> name.value
  ),
  publishTo := {
    if (isSnapshot.value) Some("central-snapshots".at("https://central.sonatype.com/repository/maven-snapshots/"))
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
