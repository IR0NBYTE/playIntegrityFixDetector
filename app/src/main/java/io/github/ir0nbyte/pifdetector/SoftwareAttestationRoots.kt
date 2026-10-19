package io.github.ir0nbyte.pifdetector

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * The AOSP software attestation roots, carried so a chain that ends in one can
 * be NAMED rather than merely found unfamiliar.
 *
 * These are not trust anchors and must never be added to
 * [AttestationRoots.pinnedRoots]. They are the opposite: the two self-signed
 * certificates that AOSP compiles into its software KeyMaster, so a device with
 * no secure environment can still answer an attestation request. Every
 * emulator image on the bench serves them, and that is correct behaviour for an
 * emulator.
 *
 * Both certificates are byte copies of `kEcAttestRootCert` and
 * `kRsaAttestRootCert` in `contexts/soft_attestation_cert.cpp`, read from
 * platform/system/keymaster at `main` (24429 bytes, sha256
 * 3c93f9a809f0b35b...). The C arrays were decoded to DER and wrapped here; the
 * SHA-256 of each certificate is asserted in [SoftwareAttestationRootsTest] so
 * a re-wrap that changed a byte fails the build instead of quietly narrowing
 * what this build can recognise.
 *
 * Why recognising them is worth any code at all: the two algorithms do not
 * share a root here. The EC chain ends in "Android Keystore Software
 * Attestation Root" and the RSA chain ends in an unnamed Google, Inc. / Android
 * certificate, and they are different keys. Measured on three emulator images,
 * API 30, 32 and 34. So "one device, one attestation root" is simply not a
 * platform invariant, and any arm phrased that way would convict a stock
 * emulator. [CompanionAlgorithmCheck] is phrased against these certificates by
 * name instead.
 */
object SoftwareAttestationRoots {

    private val ROOT_PEMS = listOf(

        // kEcAttestRootCert. Self-signed, 2016-01-11 to 2036-01-06,
        // CN=Android Keystore Software Attestation Root.
        """-----BEGIN CERTIFICATE-----
MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll
dzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYD
VQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3Qw
HhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
BgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwq
QW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59
dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0O
BBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0W
EOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqG
SM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBN
C/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==
-----END CERTIFICATE-----""",

        // kRsaAttestRootCert. Self-signed, 2016-01-04 to 2035-12-30, no CN.
        // This is the one OhMyKeymint serves for RSA when a keybox carries no
        // RSA entry.
        """-----BEGIN CERTIFICATE-----
MIICpzCCAhCgAwIBAgIJAP+U2d2fB8gMMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBW
aWV3MRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQwHhcN
MTYwMTA0MTIzMTA4WhcNMzUxMjMwMTIzMTA4WjBjMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UE
CgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMfd5tjkWP/96r/C3JHTsAs
Q+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmgMdsGUmX4RFlXYfC78hdL
t0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm+Vfkl5YLCazOkjWFmwID
AQABo2MwYTAdBgNVHQ4EFgQUKfrxrMxN0kyWQCd1trDpMuUH/i4wHwYDVR0jBBgw
FoAUKfrxrMxN0kyWQCd1trDpMuUH/i4wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAoQwDQYJKoZIhvcNAQELBQADgYEAT3LzNlmNDsG5dFsxWfbwjSVJMJ6j
HBwp0kUtILlNX2S06IDHeHqcOd6os/W/L3BfRxBcxebrTQaZYdKumgf/93y4q+uc
DyQHXrF/unlx/U1bnt8Uqf7f7XzAiF343ZtkMlbVNZriE/mPzsF83O+kqrJVw4Op
Lvtc9mL1J1IXvmM=
-----END CERTIFICATE-----"""
    )

    /**
     * Parsed once. An empty list on any parse failure, which fails the arm
     * closed: nothing can be identified as a software root, so nothing fires.
     */
    val roots: List<X509Certificate> by lazy {
        try {
            val cf = CertificateFactory.getInstance("X.509")
            ROOT_PEMS.mapNotNull { pem ->
                try {
                    cf.generateCertificate(ByteArrayInputStream(pem.toByteArray(Charsets.US_ASCII)))
                        as? X509Certificate
                } catch (_: Exception) {
                    null
                }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }
}
