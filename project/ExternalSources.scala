import sbt.*

// Manages external git repository checkouts required at build time.
// Pinned by exact commit SHA for reproducible builds. Cloned to .lib/ at the project root
// (gitignored via the .* pattern). Persistent across sbt clean.
object ExternalSources {

  case class GitSource(repo: String, commit: String, label: String)

  // Wycheproof test vectors (C2SP fork)
  val wycheproof: GitSource = GitSource(
    repo = "https://github.com/C2SP/wycheproof.git",
    commit = "45d916899992c5e42dba75106104ca8ce7ff8370",
    label = "2025-03-28 HEAD"
  )

  // PHC Argon2 reference C implementation
  val phcArgon2: GitSource = GitSource(
    repo = "https://github.com/P-H-C/phc-winner-argon2.git",
    commit = "62358ba2123abd17fccf2a108a301d4b52c01a7c",
    label = "20190702"
  )

  // Resolves a GitSource to a local directory, cloning if absent or stale.
  def resolve(source: GitSource, rootDir: File, log: sbt.util.Logger): File = {
    val repoName = source.repo.split('/').last.stripSuffix(".git")
    val target = rootDir / ".lib" / repoName
    val commitMarker = target / ".kufuli-commit"

    if (target.exists() && commitMarker.exists() && IO.read(commitMarker).trim == source.commit) {
      log.debug(s"ExternalSources: $repoName @ ${source.label} already checked out")
      target
    } else {
      if (target.exists()) {
        log.info(s"ExternalSources: removing stale checkout of $repoName")
        IO.delete(target)
      }
      log.info(s"ExternalSources: cloning $repoName @ ${source.label} (${source.commit.take(12)})")

      IO.createDirectory(target)
      run(Seq("git", "init"), target, log)
      run(Seq("git", "remote", "add", "origin", source.repo), target, log)
      run(Seq("git", "fetch", "--depth", "1", "origin", source.commit), target, log)
      run(Seq("git", "checkout", "FETCH_HEAD"), target, log)

      IO.write(commitMarker, source.commit)
      log.info(s"ExternalSources: $repoName ready at $target")
      target
    }
  }

  private def run(args: Seq[String], cwd: File, log: sbt.util.Logger): Unit = {
    import scala.sys.process.*
    val processLog = ProcessLogger(
      out => log.info(s"ExternalSources: $out"),
      err => if (!err.contains("detached HEAD")) log.warn(s"ExternalSources: $err")
    )
    val exitCode = Process(args, cwd).!(processLog)
    if (exitCode != 0)
      sys.error(s"ExternalSources: command failed (exit $exitCode): ${args.mkString(" ")}")
  }
}
