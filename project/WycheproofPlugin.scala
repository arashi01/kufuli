import sbt.*
import sbt.Keys.*

/** Embeds Wycheproof JSON test vector files as string constants in generated Scala source, enabling
  * cross-platform (JVM, JS, Native) test vector consumption without `getResourceAsStream`.
  *
  * Enable on a project, then configure:
  * {{{
  * .enablePlugins(WycheproofPlugin)
  * .settings(
  *   wycheproofTargetPackage := "my.package.wycheproof",
  *   wycheproofVectorFiles := Seq("hmac_sha256_test.json", ...)
  * )
  * }}}
  *
  * The Wycheproof repository is automatically cloned on first build via [[ExternalSources]]. For
  * each listed `.json` file, generates a Scala object containing the raw JSON as a string constant.
  * Suites parse this at runtime via jsoniter-scala `readFromString`.
  */
object WycheproofPlugin extends AutoPlugin {

  object autoImport {
    val wycheproofVectorFiles = settingKey[Seq[String]](
      "List of JSON filenames to embed from the Wycheproof testvectors_v1/ directory."
    )
    val wycheproofTargetPackage = settingKey[String](
      "Scala package for generated vector objects."
    )
    val wycheproofGenerate = taskKey[Seq[File]](
      "Generates Scala source files embedding Wycheproof JSON vectors."
    )
  }

  import autoImport.*

  override def trigger = noTrigger

  override def requires = plugins.JvmPlugin

  override def projectSettings: Seq[Setting[?]] = Seq(
    wycheproofVectorFiles := Seq.empty,
    wycheproofTargetPackage := "wycheproof"
  ) ++ inConfig(Test)(
    Seq(
      wycheproofGenerate := {
        val files = wycheproofVectorFiles.value
        val targetPkg = wycheproofTargetPackage.value
        val outDir = sourceManaged.value / "wycheproof"
        val log = streams.value.log
        val cacheDir = streams.value.cacheDirectory / "wycheproof"
        val rootDir = (LocalRootProject / baseDirectory).value

        if (files.isEmpty) Seq.empty[File]
        else {
          // Resolve Wycheproof checkout (clones on first build)
          val repoDir = ExternalSources.resolve(ExternalSources.wycheproof, rootDir, log)
          val vectorDir = repoDir / "testvectors_v1"

          IO.createDirectory(outDir)
          files.map { filename =>
            val jsonFile = vectorDir / filename
            if (!jsonFile.exists())
              sys.error(s"Wycheproof vector file not found: $jsonFile")

            val objectName = filenameToObjectName(filename)
            val outFile = outDir / s"$objectName.scala"
            val tempFile = cacheDir / s"$objectName.scala"

            // Generate to temp, then copy only if content changed (avoids needless recompilation)
            IO.createDirectory(cacheDir)
            val content = IO.read(jsonFile)
            val scalaSource = renderSource(targetPkg, objectName, filename, content)
            IO.write(tempFile, scalaSource, IO.utf8)

            val changed = !outFile.exists() || !IO.readBytes(outFile).sameElements(IO.readBytes(tempFile))
            if (changed) {
              log.info(s"WycheproofPlugin: generating $objectName from $filename")
              IO.copyFile(tempFile, outFile, preserveLastModified = true)
            }
            outFile
          }
        }
      },
      sourceGenerators += wycheproofGenerate.taskValue
    )
  )

  /** JVM class file constant pool limits UTF8 entries to 65535 bytes. Split large strings into
    * chunks that stay under this limit, then concatenate at runtime via `StringBuilder`.
    */
  private val MaxChunkBytes = 60000 // conservative margin under 65535

  private def renderSource(pkg: String, objectName: String, filename: String, jsonContent: String): String = {
    val escaped = escapeTripleQuote(jsonContent)
    if (escaped.getBytes("UTF-8").length <= MaxChunkBytes) {
      s"""|package $pkg
          |
          |/** Generated from `$filename`. Do not edit. */
          |object $objectName:
          |  val json: String = ${"\"\"\""}$escaped${"\"\"\""}
          |""".stripMargin
    } else {
      val chunks = splitByByteLimit(escaped, MaxChunkBytes)
      val sb = new StringBuilder
      sb.append(s"package $pkg\n\n")
      sb.append(s"/** Generated from `$filename`. Do not edit. */\n")
      sb.append(s"object $objectName:\n")
      sb.append(s"  val json: String =\n")
      sb.append(s"    val sb = new StringBuilder(${jsonContent.length})\n")
      chunks.zipWithIndex.foreach { case (chunk, _) =>
        sb.append(s"""    sb.append(${"\"\"\""}$chunk${"\"\"\""})\n""")
      }
      sb.append(s"    sb.result()\n")
      sb.result()
    }
  }

  /** Converts `hmac_sha256_test.json` -> `HmacSha256TestJson`. */
  private def filenameToObjectName(filename: String): String = {
    val base = filename.stripSuffix(".json")
    base
      .split("[_\\-]")
      .map(segment => segment.take(1).toUpperCase + segment.drop(1))
      .mkString + "Json"
  }

  /** Escapes triple-quote sequences inside JSON content so the Scala string literal is valid. */
  private def escapeTripleQuote(s: String): String =
    s.replace("\"\"\"", "\\\"\\\"\\\"")

  /** Splits a string into chunks where each chunk's UTF-8 byte encoding is <= maxBytes. */
  private def splitByByteLimit(s: String, maxBytes: Int): Seq[String] = {
    val result = Vector.newBuilder[String]
    val current = new StringBuilder
    var currentBytes = 0
    var i = 0
    while (i < s.length) {
      val c = s.charAt(i)
      val charBytes = if (c <= 0x7f) 1 else if (c <= 0x7ff) 2 else 3
      if (currentBytes + charBytes > maxBytes && current.nonEmpty) {
        result += current.result()
        current.clear()
        currentBytes = 0
      }
      current.append(c)
      currentBytes += charBytes
      i += 1
    }
    if (current.nonEmpty) result += current.result()
    result.result()
  }
}
