SIGNED OFFLINE WINDOWS UPDATE PACKAGE

1. Fully extract this ZIP on the disconnected Windows computer.
2. Obtain the signer's SHA-256 certificate fingerprint from the package creator
   through a separate trusted channel. Do not trust a fingerprint copied only
   from this ZIP. The Windows certificate chain must already trust the signer.
3. Before running any launcher, inspect Install-OfflineUpdates.ps1 with
   Get-AuthenticodeSignature. Its status must be Valid and its signer must
   match the independently verified certificate. Do not bypass AllSigned or
   run the script if Windows reports an invalid or unknown signature.
4. Verify that every MSU/CAB was obtained from Microsoft Update Catalog and
   matches the target Windows edition, build, architecture and prerequisites.
   The online scan describes the source computer, not the offline target.
   Review the applicable license terms for each update before installation;
   this installer does not display those terms.
5. Run Verify-OfflineUpdates.cmd and enter the independently verified
   64-character fingerprint when prompted. This verifies the RSA-signed
   manifest and all listed file hashes.
6. Right-click Install-OfflineUpdates.cmd and choose Run as administrator.
   Enter the same fingerprint, then type INSTALL to confirm acceptance of the
   terms and start installation.
   Windows servicing tools (WUSA/DISM) apply their own trust and applicability
   checks. CAB files must be Windows servicing packages, not driver CABs.
7. Packages are processed in the chosen order. If a restart is required,
   restart the computer and run the installer again. A failed or inapplicable
   package stops the sequence; check prerequisites and Windows history. If
   appropriate, create a new package containing only the remaining files.

The script does not download anything or automatically restart the computer.
Its log and restart state are kept in:
%ProgramData%\BezpiecznyAktualizator\OfflineUpdates\<package-id>

The manifest signature authenticates the manifest only when its certificate
fingerprint was obtained independently and the PowerShell signer is trusted by
Windows. SHA-256 checks detect changes to files listed in the signed manifest.
The update/CVE references are informational and do not prove that the selected
files correspond to those updates.
