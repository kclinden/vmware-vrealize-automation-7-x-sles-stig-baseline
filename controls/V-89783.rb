control "V-89783" do
  title "The SLES for vRealize must off-load audit records onto a different
system or media from the system being audited."
  desc  "Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.
  "
  impact 0.3
  tag "severity": nil
  tag "gtitle": "SRG-OS-000342-GPOS-00133"
  tag "gid": "V-89783"
  tag "rid": "SV-100433r1_rule"
  tag "stig_id": "VRAU-SL-001060"
  tag "fix_id": "F-96525r1_fix"
  tag "cci": ["CCI-001851"]
  tag "nist": ["AU-4 (1)", "Rev_4"]
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
  tag "check": "Check the syslog configuration file for remote syslog servers:

# cat /etc/syslog-ng/syslog-ng.conf | grep logserver

If no line is returned, or \"logserver\" is commented out, this is a finding."
  tag "fix": "Edit the syslog configuration file and add an appropriate remote
syslog server:

In the /etc/syslog-ng/syslog-ng.conf file, the remote logging entries must be
uncommented and the IP address must be modified to point to the remote syslog
server:

#
# Enable this and adopt IP to send log messages to a log server.
#
destination logserver { udp(\"x.x.x.x\" port(514)); };
log { source(src); destination(logserver); };

Note: Replace x.x.x.x with the appropriate IP address."
end

