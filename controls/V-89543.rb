control "V-89543" do
  title "The SLES for vRealize must generate audit records when
successful/unsuccessful attempts to access privileges occur. The SLES for
vRealize must generate audit records for all discretionary access control
permission modifications using fchown."
  desc  "Without generating audit records that are specific to the security and
mission needs of the organization, it would be difficult to establish,
correlate, and investigate the events relating to an incident or identify those
responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000064-GPOS-00033"
  tag "gid": "V-89543"
  tag "rid": "SV-100193r1_rule"
  tag "stig_id": "VRAU-SL-000275"
  tag "fix_id": "F-96285r2_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "To determine if the system is configured to audit calls to the
\"fchown\" system call, run the following command:

# auditctl -l | grep syscall | grep fchown

If the system is configured to audit this activity, it will return several
lines, such as:

LIST_RULES: exit,always arch=3221225534 (0xc000003e) auid=0
syscall=chmod,fchmod,chown,fchown,fchownat,fchmodat
LIST_RULES: exit,always arch=3221225534 (0xc000003e) auid>=500 (0x1f4) auid!=-1
(0xffffffff) syscall=chmod,fchmod,chown,fchown,fchownat,fchmodat

If no lines are returned, this is a finding."
  tag "fix": "At a minimum, the SLES for vRealize audit system should collect
file permission changes for all users and \"root\". Add the following to
\"/etc/audit/audit.rules\":

-a always,exit -F arch=b64 -S fchown -F auid=0
-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295
-a always,exit -F arch=b32 -S fchown
-a always,exit -F arch=b32 -S fchown32

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh"

describe file("/etc/audit/audit.rules") do
  its("content") { should match %r{-S fchown} } #this may be too exclusive, and might need to be expanded.
  its("content") { should match %r{-S fchown32} } #this may be too exclusive, and might need to be expanded.
end

end

