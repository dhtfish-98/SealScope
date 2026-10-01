"""sealscope — structural audit of Mach-O code signatures and entitlements.

What it reports: whether a binary is signed and how, which protections its declared
signature flags and entitlements give up, whether the signature metadata covers the
file, and — for a bundle — whether the resources it sealed still match. These are
claims in the signature. What it does not do: verify the CMS signature or the
certificate chain, or establish which permissions the operating system actually
grants. ``codesign -v`` checks whether the claim is true.

    from sealscope import audit_file, audit_bundle
    report = audit_file("/usr/bin/otool")
    for finding in report.findings:
        print(finding.severity, finding.title)

    bundle = audit_bundle("/Applications/Example.app")
"""
from .inspection import FileReview as FileReview, ImageReview as ImageReview, inspect_bundle as inspect_bundle, inspect_buffer as inspect_buffer, inspect_file as inspect_file
from .observations import Observation as Observation, RiskLevel as RiskLevel
__version__ = '0.2.0'
__all__ = ['inspect_file', 'inspect_buffer', 'inspect_bundle', 'FileReview', 'ImageReview', 'Observation', 'RiskLevel', '__version__']
