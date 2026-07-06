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

  /** Test-binary link settings: only musl can produce a fully static executable, and only when CI
    * asks.
    */
  val testLinkSettings: Seq[Setting[?]] = schemeSettings ++ Seq(
    Test / SNX.modifiers += Modifier.platform {
      case Linux(_, Musl) if staticLink => _.linkOptions("-static")
    }
  )

}
