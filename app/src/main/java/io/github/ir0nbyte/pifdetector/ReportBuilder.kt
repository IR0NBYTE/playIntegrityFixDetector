package io.github.ir0nbyte.pifdetector

/**
 * The plain-text report a user attaches to an issue.
 *
 * Until now the only thing anyone could send was a screenshot, which shows the
 * verdicts and none of the evidence: not which arm fired, not what the chain
 * looked like, not how old the bundled revocation snapshot was. Every one of
 * those is the first question worth asking about a report.
 *
 * Deliberately plain text. It gets pasted into issues and chat windows, so it
 * has to survive both, and a person has to be able to read it without a tool.
 *
 * No serial numbers, no attestation challenge, no certificate bytes. The point
 * is to explain a verdict, and none of those is needed to do that.
 */
object ReportBuilder {

    private const val RULE = "----------------------------------------"

    fun build(
        rows: List<DetectionResult>,
        report: DetectionReport,
        presentation: DeviceIdentity.Presentation,
        appVersion: String,
    ): String = buildString {
        appendLine("PIF Detector report")
        appendLine(RULE)
        appendLine()

        appendSummary(rows)
        appendLine()
        appendDevice(presentation, appVersion)
        appendLine()
        appendAttestation(report)
        appendLine()
        appendChecks(rows)
    }

    private fun StringBuilder.appendSummary(rows: List<DetectionResult>) {
        val findings = rows.count { it.state.isFinding }
        val review = rows.count { it.state.needsReview }
        val unobservable = rows.count { !it.state.isObservable }
        val clean = rows.count { it.state == CheckState.CLEAN }

        appendLine("SUMMARY")
        appendLine("  findings       $findings")
        appendLine("  needs review   $review")
        appendLine("  passed         $clean")
        appendLine("  not observable $unobservable")
    }

    private fun StringBuilder.appendDevice(
        p: DeviceIdentity.Presentation,
        appVersion: String,
    ) {
        appendLine("DEVICE")
        appendLine("  app              $appVersion")
        appendLine("  fingerprint      ${orUnknown(p.fingerprint)}")
        appendLine("  brand/model      ${orUnknown(p.brand)} / ${orUnknown(p.model)}")
        appendLine("  board/hardware   ${orUnknown(p.board)} / ${orUnknown(p.hardware)}")
        appendLine("  build type/tags  ${orUnknown(p.buildType)} / ${orUnknown(p.buildTags)}")
        appendLine("  sdk              ${p.sdkInt}")
        appendLine("  hardware keystore declared  ${p.hardwareKeystoreDeclared}")
        appendLine("  presents as release build   ${p.releaseBuild}")
    }

    private fun StringBuilder.appendAttestation(report: DetectionReport) {
        appendLine("ATTESTATION")

        val revocation = report.revocation
        val snapshot = revocation.snapshotDate?.let {
            "$it (${revocation.snapshotEntryCount} entries)"
        } ?: "none bundled"
        appendLine("  revocation outcome   ${revocation.outcome}")
        appendLine("  revocation snapshot  $snapshot")
        appendLine("  network consulted    ${revocation.networkConsulted}")

        val cross = report.crossSource
        if (cross != null) {
            appendLine("  cross-source evaluated  ${cross.evaluated}")
            cross.attestedBootPatchLevel?.let { appendLine("  attested boot patch     $it") }
        }
        report.validity?.let { appendLine("  chain validity          ${it.outcome}") }
        report.versions?.let { v ->
            appendLine("  attested schema         ${v.attestationVersion ?: "?"}")
            appendLine("  attested KeyMint        ${v.keymasterVersion ?: "?"}")
        }
        report.moduleHash?.let { appendLine("  module hash             ${it.outcome}") }
    }

    private fun StringBuilder.appendChecks(rows: List<DetectionResult>) {
        appendLine("CHECKS")
        for (row in rows) {
            appendLine("  [${label(row.state)}] ${row.name}")
            row.detail?.takeIf { it.isNotEmpty() }?.let {
                appendLine("        ${wrap(it)}")
            }
            // The reasons are the part a screenshot could never carry.
            for (reason in row.reasons) {
                appendLine("        - $reason")
            }
        }
    }

    /** Fixed width so the states line up when pasted into a proportional font. */
    private fun label(state: CheckState): String = when (state) {
        CheckState.DETECTED -> "DETECTED      "
        CheckState.INFORMATIONAL -> "REPORTED      "
        CheckState.UNVERIFIABLE -> "UNVERIFIABLE  "
        CheckState.SKIPPED -> "SKIPPED       "
        CheckState.NOT_OBSERVABLE -> "NOT OBSERVABLE"
        CheckState.CLEAN -> "PASS          "
    }

    private fun orUnknown(value: String): String = value.ifEmpty { "unknown" }

    /** Keeps a long detail readable without needing a wide terminal. */
    private fun wrap(text: String, width: Int = 76): String {
        if (text.length <= width) return text
        val out = StringBuilder()
        var line = 0
        for (word in text.split(" ")) {
            if (line + word.length + 1 > width) {
                out.append("\n        ")
                line = 0
            } else if (line > 0) {
                out.append(' ')
                line++
            }
            out.append(word)
            line += word.length
        }
        return out.toString()
    }
}
