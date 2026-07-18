import sbt.*
import sbt.Keys.*

import snx.sbt.SNXImports.*

/** sbt-snx wiring for kufuli's native rows: test-interface eviction scheme and static test
  * binaries.
  */
object NativePlatformPlugin {

  /** Set by CI for the musl-static cells; absent or unset for every dynamic build. */
  private val staticLink: Boolean = sys.env.get("KUFULI_STATIC_LINK").contains("true")

  /** The scala-native test-interface carries no semver scheme; `always` stops eviction failing the
    * build.
    */
  val schemeSettings: Seq[Setting[?]] = Seq(
    libraryDependencySchemes += "org.scala-native" % "test-interface_native0.5_3" % "always"
  )

  /** Declares that the Native backend needs `crypto` (aws-lc). Exported in the NIR descriptor so a
    * downstream consumer provisions it once with `SNX.libraries += KufuliNative.awsLc`; a consumer
    * whose system libcrypto is aws-lc rebinds the name to System instead.
    */
  val exportCrypto: Seq[Setting[?]] = Seq(SNX.libraries += NativeLibrary("crypto"))

  /** Provisions aws-lc from source for kufuli's own binding tests (scoped to the test link, as a
    * NIR library publishes its C as source rather than exporting a vendored build).
    */
  val provisionAwsLc: Seq[Setting[?]] = Seq(SNX.libraries += KufuliNative.awsLc % Test)

  /** Test-binary link settings: only musl can produce a fully static executable, and only when CI
    * asks.
    */
  val testLinkSettings: Seq[Setting[?]] = schemeSettings ++ Seq(
    Test / SNX.modifiers += Modifier.platform {
      case Linux(_, Musl) if staticLink => _.linkOptions("-static")
    }
  )

}
