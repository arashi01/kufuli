import sbt.*

import scala.sys.process.Process
import scala.sys.process.ProcessLogger

import snx.sbt.SNXImports.*

/** kufuli's native provisioning recipes. sbt-snx is the mechanism (a pkg-config analogue); these
  * are the recipes it carries, shipped so a consumer provisions each Native backend in one line:
  * {{{
  * SNX.libraries += KufuliNative.awsLc      // core
  * SNX.libraries += KufuliNative.argon2     // kufuli-password
  * }}}
  */
object KufuliNative {

  /** The aws-lc release kufuli is verified against. */
  val awsLcTag: String = "v5.2.0"

  private val awsLcRepository: String = "https://github.com/aws/aws-lc.git"

  /** Crypto-only, reproducible. `BUILD_LIBSSL`, `BUILD_TOOL` and `BUILD_TESTING` each default ON;
    * leaving `BUILD_LIBSSL`/`BUILD_TESTING` on would also pull in a C++ toolchain the crypto build
    * does not otherwise need. `DISABLE_PERL=OFF` makes Perl a `find_package(REQUIRED)` hard
    * failure, and `ENABLE_SOURCE_MODIFICATION` defaults ON and writes into the checkout, which a
    * pinned build must not do. sbt-snx supplies `CMAKE_BUILD_TYPE` and forces
    * `BUILD_SHARED_LIBS=OFF` itself.
    */
  private val configureFlags: Seq[String] = Seq(
    "-DBUILD_LIBSSL=OFF",
    "-DBUILD_TOOL=OFF",
    "-DBUILD_TESTING=OFF",
    "-DDISABLE_GO=ON",
    "-DDISABLE_PERL=ON",
    "-DENABLE_SOURCE_MODIFICATION=OFF",
    "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
  )

  /** aws-lc assembles with NASM on Windows and its CMake Visual Studio generator cannot assemble at
    * all, so the build must be driven by Ninja from an environment where the MSVC toolchain is
    * already on PATH (`vcvarsall.bat`). sbt-snx's CMake backend never passes `-DCMAKE_C_COMPILER`,
    * so an `SNX.clang` override would not reach this build (sbt-snx #19) - the discovered PATH
    * compiler must itself be the MSVC one.
    */
  private val windowsFlags: Seq[String] = Seq("-GNinja", "-DCMAKE_ASM_NASM_COMPILER=nasm")

  /** The link closure a static archive cannot carry itself. */
  private val closure: PartialFunction[NativeRuntime, Flags] = { case Linux(_, _) =>
    Flags.libraries("pthread", "dl")
  }

  /** aws-lc, built from source at a pinned tag and folded into the link.
    *
    * The name is `crypto` deliberately: it is both the rebind key and the `-l` name a System
    * provisioning renders, which is what lets a consumer whose system libcrypto IS aws-lc rebind to
    * `NativeLibrary("crypto")` instead. A consumer who provisions neither links stock libcrypto and
    * fails loudly - kufuli's C shim is written to the BoringSSL-dialect surface, and asserts
    * `OPENSSL_IS_AWSLC` at compile time before that.
    */
  val awsLc: NativeLibrary =
    NativeLibrary(
      "crypto",
      Vendored
        .git(awsLcRepository, awsLcTag)
        .cmake(
          Seq("crypto"),
          {
            case Windows(_, _) => configureFlags ++ windowsFlags
            case _             => configureFlags
          }
        )
        .options(closure)
    )

  /** The libargon2 release kufuli is verified against (matches the `vendor/phc-winner-argon2`
    * submodule commit).
    */
  val argon2Tag: String = "20190702"

  private val argon2Repository: String = "https://github.com/P-H-C/phc-winner-argon2.git"

  /** Build libargon2 as a static archive with the reference Makefile.
    *
    * `NO_THREADS=1` computes every lane on the calling thread: the Argon2id output depends on the
    * lane count, not on how many OS threads compute them, so the hash is byte-identical while the
    * build gains no pthread dependency (and never spawns a thread on the musl static row).
    * `OPTTARGET=` empties the Makefile's `-march`, so the archive is the compiler's default
    * baseline rather than `-march=native` - reproducible and safe to cross-compile. sbt-snx
    * requires a backend to write its outputs under the context staging directory, so the source is
    * copied there and built out of the cached clone.
    */
  private def buildArgon2(context: BuildContext): Artefacts = {
    val buildDir = context.staging / "build"
    IO.copyDirectory(context.source, buildDir)
    val command = Seq(
      "make",
      "-C",
      buildDir.getAbsolutePath,
      "libargon2.a",
      s"CC=${context.clang.getAbsolutePath}",
      "NO_THREADS=1",
      "OPTTARGET="
    )
    context.log.info(command.mkString("snx argon2: ", " ", ""))
    val logger = ProcessLogger(line => context.log.info(line), line => context.log.error(line))
    if (Process(command).!(logger) != 0)
      sys.error(s"snx: libargon2 build failed: ${command.mkString(" ")}")
    val archive = buildDir / "libargon2.a"
    if (!archive.isFile) sys.error(s"snx: libargon2 build produced no archive at ${archive.getAbsolutePath}")
    Artefacts(Seq(archive), Seq(buildDir / "include"))
  }

  /** libargon2, built from source at a pinned tag and folded into the link.
    *
    * The name is `argon2`, both the rebind key and the `-l` name, so a consumer whose system
    * already provides libargon2 can rebind `NativeLibrary("argon2")` to System instead of vendoring
    * it. The Argon2id primitive is a frozen deterministic spec (RFC 9106), so a vendored provider
    * agrees byte-for-byte with any other conformant one; `kufuli.password`'s PHC codec and policy
    * sit in shared Scala above it.
    */
  val argon2: NativeLibrary =
    NativeLibrary(
      "argon2",
      Vendored
        .git(argon2Repository, argon2Tag)
        .command("libargon2-static-ref-nothreads-1")(buildArgon2)
    )
}
