import sbt.*

import snx.sbt.SNXImports.*

/** kufuli's aws-lc provisioning recipe. sbt-snx is the mechanism (a pkg-config analogue); this is
  * the recipe it carries, shipped so a consumer provisions the Native backend in one line:
  * {{{
  * SNX.libraries += KufuliNative.awsLc
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
}
