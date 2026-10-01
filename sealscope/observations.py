"""The finding type and the entitlement risk table.

Severity here means "how much of the platform's protection does this claim give up",
not "is this a vulnerability". A JIT entitlement on a browser is expected and correct;
the same entitlement on a document converter is worth a question. The tool reports
the entitlements and hardening settings a binary declares, and why that claim matters.
It does not establish which permissions the operating system actually grants.
Deciding whether a claim is appropriate is the reader's job, and every finding is
phrased so the reader can make that call.
"""
from __future__ import annotations as seal_annotations
from dataclasses import dataclass as seal_dataclass, field as seal_field
from typing import Any as seal_Any, Dict as seal_Dict, List as seal_List, Optional as seal_Optional
__all__ = ['RiskLevel', 'Observation', 'SEAL_ENTITLEMENT_RISKS', 'seal_entitlement_risk', 'SEAL_SEVERITY_ORDER']

class RiskLevel:
    SEAL_HIGH = 'high'
    SEAL_MEDIUM = 'medium'
    SEAL_LOW = 'low'
    SEAL_INFO = 'info'
SEAL_SEVERITY_ORDER = {RiskLevel.SEAL_HIGH: 0, RiskLevel.SEAL_MEDIUM: 1, RiskLevel.SEAL_LOW: 2, RiskLevel.SEAL_INFO: 3}

@seal_dataclass
class Observation:
    seal_id: str
    seal_severity: str
    seal_title: str
    seal_detail: str
    seal_arch: seal_Optional[str] = None
    seal_evidence: seal_Dict[str, seal_Any] = seal_field(default_factory=dict)

    def export_record(record) -> seal_Dict[str, seal_Any]:
        seal_d = {'id': record.seal_id, 'severity': record.seal_severity, 'title': record.seal_title, 'detail': record.seal_detail}
        if record.seal_arch:
            seal_d['arch'] = record.seal_arch
        if record.seal_evidence:
            seal_d['evidence'] = record.seal_evidence
        return seal_d
SEAL_ENTITLEMENT_RISKS: seal_Dict[str, tuple] = {'com.apple.security.get-task-allow': (RiskLevel.SEAL_HIGH, 'Any process running as the same user can attach to this one and read or write its memory. Expected in a debug build; in shipping code it removes the barrier that keeps other processes out.'), 'com.apple.security.cs.debugger': (RiskLevel.SEAL_HIGH, 'This binary may attach to and control other processes as a debugger.'), 'com.apple.security.cs.disable-library-validation': (RiskLevel.SEAL_HIGH, 'The process may load libraries signed by anyone, not just by the same team or by Apple. This is the protection that stops an attacker-planted dylib from being loaded into it.'), 'com.apple.security.cs.allow-unsigned-executable-memory': (RiskLevel.SEAL_HIGH, 'The process may create writable-then-executable memory, so code that was never signed can run in it.'), 'com.apple.security.cs.disable-executable-page-protection': (RiskLevel.SEAL_HIGH, "Executable pages may be made writable, so the process's own code can be rewritten after it is mapped. This is the broadest of the hardened-runtime exceptions."), 'com.apple.security.cs.allow-dyld-environment-variables': (RiskLevel.SEAL_HIGH, 'DYLD_* environment variables are honoured, so whoever launches this process can force extra libraries into it.'), 'com.apple.private.security.no-sandbox': (RiskLevel.SEAL_HIGH, 'The process is exempt from sandboxing.'), 'task_for_pid-allow': (RiskLevel.SEAL_HIGH, 'The process may obtain the task port of other processes, which grants full read/write access to their memory.'), 'platform-application': (RiskLevel.SEAL_HIGH, 'The process is treated as an Apple platform binary, which relaxes several checks that apply to third-party code.'), 'com.apple.security.cs.allow-jit': (RiskLevel.SEAL_MEDIUM, 'The process may map JIT memory (MAP_JIT). Expected for a JavaScript or language runtime; unusual anywhere else.'), 'com.apple.system-task-ports': (RiskLevel.SEAL_MEDIUM, 'The process may obtain task ports for system processes.'), 'com.apple.security.cs.allow-relative-library-loads': (RiskLevel.SEAL_MEDIUM, 'Libraries may be loaded by relative path, which widens where a planted library could be picked up from.'), 'com.apple.private.tcc.allow': (RiskLevel.SEAL_MEDIUM, 'The process is granted TCC-protected access without prompting the user.'), 'com.apple.rootless.install': (RiskLevel.SEAL_MEDIUM, 'The process may write to paths protected by System Integrity Protection.'), 'com.apple.rootless.install.heritable': (RiskLevel.SEAL_MEDIUM, 'The process, and anything it spawns, may write to SIP-protected paths.'), 'keychain-access-groups': (RiskLevel.SEAL_LOW, 'Declares which keychain groups the process shares items with.'), 'com.apple.security.app-sandbox': (RiskLevel.SEAL_INFO, 'The process runs inside the App Sandbox.')}
SEAL__PREFIX_RISKS = [('com.apple.security.temporary-exception.', RiskLevel.SEAL_MEDIUM, "A temporary sandbox exception: a hole deliberately punched in this process's sandbox. Worth checking that the exception is still needed and is no wider than it has to be."), ('com.apple.security.cs.', RiskLevel.SEAL_MEDIUM, 'A hardened-runtime exception: it switches off one of the protections the hardened runtime would otherwise apply.'), ('com.apple.private.', RiskLevel.SEAL_LOW, 'An Apple-private entitlement. Third-party code cannot obtain one, so on a non-Apple binary this is worth explaining.'), ('com.apple.security.device.', RiskLevel.SEAL_INFO, 'A sandbox grant for device access (camera, microphone, USB and similar).'), ('com.apple.security.files.', RiskLevel.SEAL_INFO, 'A sandbox grant for file access.'), ('com.apple.security.network.', RiskLevel.SEAL_INFO, 'A sandbox grant for network access.')]

def seal_entitlement_risk(seal_key: str, seal_value: seal_Any) -> seal_Optional[tuple]:
    """Return ``(severity, note)`` for an entitlement, or ``None`` if unremarkable.

    A key whose value is explicitly false grants nothing, so it is not reported as
    a risk — but it is still listed in the inventory.
    """
    if seal_value is False:
        return None
    if seal_key in SEAL_ENTITLEMENT_RISKS:
        return SEAL_ENTITLEMENT_RISKS[seal_key]
    for seal_prefix, seal_sev, seal_note in SEAL__PREFIX_RISKS:
        if seal_key.startswith(seal_prefix):
            return (seal_sev, seal_note)
    return None
