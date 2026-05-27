import sbt.*
import sbt.Keys.*

import scala.scalanative.sbtplugin.ScalaNativePlugin
import scala.scalanative.sbtplugin.ScalaNativePlugin.autoImport.nativeConfig

/** Native-build inputs that distinguish linkage targets within the Linux CI matrix.
  *
  * On Linux the toolchain ABI (glibc vs musl) and the linkage mode (dynamic vs static) are
  * orthogonal axes that must be reflected in `nativeConfig` because OpenSSL is consumed as a system
  * library (kufuli does not ship its own copy, per the library-not-application charter).
  * `KUFULI_STATIC_LINK=true` adds `-static` plus the system libraries OpenSSL requires
  * transitively, so a fully-static binary can be produced from an Alpine host with
  * `openssl-libs-static` installed. macOS uses framework linkage and Windows uses BCrypt; both fall
  * through unchanged.
  *
  * The plugin does not auto-trigger; consuming modules use these settings via
  * `NativePlatformPlugin.cryptoLinkSettings` (the file lives under `project/` so it compiles with
  * sbt's Scala 2.12 plugin classpath).
  */
object NativePlatformPlugin extends AutoPlugin {

  override def trigger: PluginTrigger = noTrigger
  override def requires: Plugins = ScalaNativePlugin

  sealed trait Os
  object Os {
    case object Linux extends Os
    case object MacOs extends Os
    case object Windows extends Os
  }

  sealed trait Libc
  object Libc {
    case object Glibc extends Libc
    case object Musl extends Libc
  }

  private val rawOs: String = sys.props.getOrElse("os.name", "").toLowerCase
  private val rawArch: String = sys.props.getOrElse("os.arch", "").toLowerCase

  val os: Os =
    if (rawOs.contains("win")) Os.Windows
    else if (rawOs.contains("mac") || rawOs.contains("darwin")) Os.MacOs
    else Os.Linux

  val archTag: String = rawArch match {
    case "x86_64" | "amd64"  => "x86_64"
    case "aarch64" | "arm64" => "aarch64"
    case other               => other
  }

  /** Linux libc detected via the musl dynamic loader's canonical path. The result is irrelevant on
    * macOS and Windows.
    */
  val libc: Libc = os match {
    case Os.Linux =>
      if (new java.io.File(s"/lib/ld-musl-$archTag.so.1").exists()) Libc.Musl else Libc.Glibc
    case _ => Libc.Glibc
  }

  /** Linkage-distinguishing host identifier, e.g. `linux-glibc-x86_64` or `linux-musl-aarch64`. */
  val hostTag: String = {
    val osPart = os match {
      case Os.Linux =>
        val libcPart = libc match {
          case Libc.Glibc => "glibc"
          case Libc.Musl  => "musl"
        }
        s"linux-$libcPart"
      case Os.MacOs   => "macos"
      case Os.Windows => "windows"
    }
    s"$osPart-$archTag"
  }

  /** Bare OS name (`linux`/`macos`/`windows`) used to select per-OS source directories. */
  val osName: String = os match {
    case Os.Linux   => "linux"
    case Os.MacOs   => "macos"
    case Os.Windows => "windows"
  }

  /** Set by CI for musl-static cells; absent or unset for all dynamic builds. */
  val staticLink: Boolean = sys.env.get("KUFULI_STATIC_LINK").contains("true")

  /** Settings that must be applied to every kufuli Native module containing or depending on the
    * platform crypto FFI. Adds OS-specific linking options to `nativeConfig`:
    *
    *   - Linux: `-lssl -lcrypto`; static cells add `-static` and the OpenSSL transitive system
    *     dependencies (`-lz -ldl -lpthread`).
    *   - macOS: `-framework Security -framework CoreFoundation`.
    *   - Windows: `-lbcrypt`.
    */
  val cryptoLinkSettings: Seq[Setting[?]] = Seq(
    nativeConfig ~= { c =>
      val base = c.withLinkingOptions(c.linkingOptions ++ baseCryptoLinkOptions)
      if (os == Os.Linux && staticLink) base.withLinkingOptions(base.linkingOptions ++ staticLinkOptions)
      else base
    }
  )

  private def baseCryptoLinkOptions: Seq[String] = os match {
    case Os.Linux   => Seq("-lssl", "-lcrypto")
    case Os.MacOs   => Seq("-framework", "Security", "-framework", "CoreFoundation")
    case Os.Windows => Seq("-lbcrypt")
  }

  /** Transitive system libraries OpenSSL pulls in via `DT_NEEDED` when statically linked. */
  private def staticLinkOptions: Seq[String] = Seq("-lz", "-ldl", "-lpthread", "-static")

  /** Adds `src/test/scala-<os>` to a Native module's test sources. Mirrors the per-OS source-dir
    * pattern boilerplate uses for its own `Platform` constant. boilerplate's published JAR bakes
    * the publisher-host's `Platform.linux` into a compile-time constant, so consumers cannot use it
    * for target-OS detection. Each kufuli CI cell builds on its actual target host, so build-host
    * detection here resolves to the right test-time platform identity.
    */
  val osTestSourceSettings: Seq[Setting[?]] = Seq(
    Test / unmanagedSourceDirectories += baseDirectory.value / "src" / "test" / s"scala-$osName"
  )

}
