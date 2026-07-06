import sbt.*
import sbt.Keys.*

import snx.sbt.SNXImports.*

/** sbt-snx native wiring for kufuli's platform crypto FFI. */
object NativePlatformPlugin {

  private val osName: String = {
    val raw = sys.props.getOrElse("os.name", "").toLowerCase
    if (raw.contains("win")) "windows"
    else if (raw.contains("mac") || raw.contains("darwin")) "macos"
    else "linux"
  }

  /** Set by CI for the musl-static cells; absent or unset for all dynamic builds. */
  private val staticLink: Boolean = sys.env.get("KUFULI_STATIC_LINK").contains("true")

  val schemeSettings: Seq[Setting[?]] = Seq(
    libraryDependencySchemes += "org.scala-native" % "test-interface_native0.5_3" % "always"
  )

  val cryptoSettings: Seq[Setting[?]] = schemeSettings ++ Seq(
    Compile / unmanagedResourceDirectories += (Compile / sourceDirectory).value / "resources-native",
    SNX.libraries := {
      case Linux(_, _)   => Seq(NativeLibrary("ssl"), NativeLibrary("crypto"))
      case Darwin(_)     => Seq(NativeLibrary.framework("Security"), NativeLibrary.framework("CoreFoundation"))
      case Windows(_, _) => Seq(NativeLibrary("bcrypt"))
    }
  )

  val testLinkSettings: Seq[Setting[?]] = schemeSettings ++ Seq(
    Test / unmanagedSourceDirectories += (Test / sourceDirectory).value / s"scalanative-$osName",
    Test / SNX.modifiers += Modifier.platform {
      case Linux(_, Musl) if staticLink => _.linkOptions("-lz", "-ldl", "-lpthread", "-static")
    }
  )

}
