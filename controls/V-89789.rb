control "V-89789" do
  title "The SLES for vRealize must, for networked systems, compare internal
information system clocks at least every 24 hours with a server which is
synchronized to one of the redundant United States Naval Observatory (USNO)
time servers, or a time server designated for the appropriate DoD network
(NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
  desc  "Inaccurate time stamps make it more difficult to correlate events and
can lead to an inaccurate analysis. Determining the correct time a particular
event occurred on a system is critical when conducting forensic analysis and
investigating system events. Sources outside the configured acceptable
allowance (drift) may be inaccurate.

    Synchronizing internal information system clocks provides uniformity of
time stamps for information systems with multiple system clocks and systems
connected over a network.

    Organizations should consider endpoints that may not have regular access to
the authoritative time server (e.g., mobile, teleworking, and tactical
endpoints).
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000355-GPOS-00143"
  tag "gid": "V-89789"
  tag "rid": "SV-100439r1_rule"
  tag "stig_id": "VRAU-SL-001110"
  tag "fix_id": "F-96531r1_fix"
  tag "cci": ["CCI-001891"]
  tag "nist": ["AU-8 (1) (a)", "Rev_4"]
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
  tag "check": "A remote NTP server should be configured for time
synchronization. To verify one is configured, open the following file:

# cat /etc/ntp.conf | grep server | grep -v '^#'
# cat /etc/ntp.conf | grep peer | grep -v '^#'
# cat /etc/ntp.conf | grep multicastclient | grep -v '^#'

Confirm the servers and peers or multicastclient (as applicable) are local or
an authoritative U.S. DoD source.

If a non-local/non-authoritative time-server is used, this is a finding."
  tag "fix": "To specify a remote NTP server for time synchronization, edit the
file \"/etc/ntp.conf\". Add or correct the following lines, substituting the IP
or hostname of a remote NTP server for \"ntpserver\" by using the following
command:

# echo \"server [ntpserver]\" >> /etc/ntp.conf

Replace [ntpserver] with one of the USNO time servers. This instructs the NTP
software to contact that remote server to obtain time data.

Restart the service with:

# service ntp restart"
end

